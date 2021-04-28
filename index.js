/*!
 * cookie-session
 * Copyright(c) 2013 Jonathan Ong
 * Copyright(c) 2014-2017 Douglas Christopher Wilson
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 * @private
 */

var Buffer = require('safe-buffer').Buffer
var debug = require('debug')('cookie-session')
var Cookies = require('cookies')
var onHeaders = require('on-headers')
const zlib = require('zlib');
const crypto = require('crypto');

/**
 * Module exports.
 * @public
 */

module.exports = cookieSession

/**
 * Create a new cookie session middleware.
 *
 * @param {object} [options]
 * @param {boolean} [options.httpOnly=true]
 * @param {array} [options.keys]
 * @param {string} [options.name=session] Name of the cookie to use
 * @param {boolean} [options.overwrite=true]
 * @param {string} [options.secret]
 * @param {boolean} [options.signed=true]
 * @return {function} middleware
 * @public
 */

function cookieSession (options) {
  var opts = options || {}

  // cookie name
  var name = opts.name || 'session'

  // secrets
  var keys = opts.keys
  if (!keys && opts.secret) keys = [opts.secret]
  opts.keys = keys;
  
  // defaults
  if (opts.overwrite == null) opts.overwrite = true
  if (opts.httpOnly == null) opts.httpOnly = true
  if (opts.signed == null) opts.signed = true

  if (!keys && opts.signed) throw new Error('.keys required.')

  debug('session options %j', opts)

  return function _cookieSession (req, res, next) {
    var cookies = new Cookies(req, res, {
      keys: keys
    })
    var sess

    // for overriding
    req.sessionOptions = Object.assign({}, opts)

    // define req.session getter / setter
    Object.defineProperty(req, 'session', {
      configurable: true,
      enumerable: true,
      get: getSession,
      set: setSession
    })

    function getSession () {
      // already retrieved
      if (sess) {
        return sess
      }

      // unset
      if (sess === false) {
        return null
      }

      // get session
      if ((sess = tryGetSession(cookies, name, req.sessionOptions))) {
        return sess
      }

      // create session
      debug('new session')
      return (sess = Session.create(null, req.sessionOptions))
    }

    function setSession (val) {
      if (val == null) {
        // unset session
        sess = false
        return val
      }

      if (typeof val === 'object') {
        // create a new session
        sess = Session.create(val, req.sessionOptions)
        return sess
      }

      throw new Error('req.session can only be set as null or an object.')
    }

    onHeaders(res, function setHeaders () {
      if (sess === undefined) {
        // not accessed
        return
      }

      try {
        if (sess === false) {
          // remove
          debug('remove %s', name)
          cookies.set(name, '', req.sessionOptions)
        } else if ((!sess.isNew || sess.isPopulated) && sess.isChanged) {
          // save populated or non-new changed session
          debug('save %s', name)
          cookies.set(name, Session.serialize(sess), req.sessionOptions)
        }
      } catch (e) {
        debug('error saving session %s', e.message)
        console.log('error saving session', e);
      }
    })

    next()
  }
};

/**
 * Session model.
 *
 * @param {Context} ctx
 * @param {Object} obj
 * @private
 */

function Session (ctx, obj) {
  Object.defineProperty(this, '_ctx', {
    value: ctx
  })

  if (obj) {
    for (var key in obj) {
      this[key] = obj[key]
    }
  }
}

/**
 * Create new session.
 * @private
 */

Session.create = function create (obj, options) {
  var ctx = new SessionContext()
  
  if (options) {
    ctx.options = options;
  }
  return new Session(ctx, obj)
}

/**
 * Create session from serialized form.
 * @private
 */

Session.deserialize = function deserialize (str, options) {
  var ctx = new SessionContext()
  var obj = decode(str, options.keys[0])

  ctx._new = false
  ctx._val = JSON.stringify(obj);

  if (options) {
    ctx.options = options;
  }
  return new Session(ctx, obj)
}

/**
 * Serialize a session to a string.
 * @private
 */

Session.serialize = function serialize (sess) {
  return encode(sess, sess._ctx.options.keys[0]);
}

/**
 * Return if the session is changed for this request.
 *
 * @return {Boolean}
 * @public
 */

Object.defineProperty(Session.prototype, 'isChanged', {
  get: function getIsChanged () {
    return this._ctx._new || this._ctx._val !== JSON.stringify(this);
  }
})

/**
 * Return if the session is new for this request.
 *
 * @return {Boolean}
 * @public
 */

Object.defineProperty(Session.prototype, 'isNew', {
  get: function getIsNew () {
    return this._ctx._new
  }
})

/**
 * populated flag, which is just a boolean alias of .length.
 *
 * @return {Boolean}
 * @public
 */

Object.defineProperty(Session.prototype, 'isPopulated', {
  get: function getIsPopulated () {
    return Object.keys(this).length > 0
  }
})

/**
 * Session context to store metadata.
 *
 * @private
 */

function SessionContext () {
  this._new = true
  this._val = undefined
}

/**
 * Decode the base64 cookie value to an object.
 *
 * @param {String} string
 * @return {Object}
 * @private
 */

function decode (string, key) {
  var body = Buffer.from(string, 'base64');
  
  if (key) {
    try {
      const iv = body.slice(body.length - 16);
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      body = Buffer.concat([decipher.update(body.slice(0, body.length - 16)), decipher.final()])      
    } catch (err) {
      console.log(err);
      return {};
    }
  }
  
  try {
    body = zlib.inflateRawSync(body).toString('utf8');    
  } catch (err) {
    console.log(err);
  }
  return JSON.parse(body)
}

/**
 * Encode an object into a base64-encoded JSON string.
 *
 * @param {Object} body
 * @return {String}
 * @private
 */

function encode (body, key) {
  try {
    var str = zlib.deflateRawSync(JSON.stringify(body));
  } catch (err) {
    console.log(err);
  }  

  if (key) {
    try {
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      str = Buffer.concat([cipher.update(str), cipher.final(), iv])      
    } catch (err) {
      console.log(err);
      return '';
    }
  }
  
  str = Buffer.from(str).toString('base64');
  
  // As it's base64 encoded - .length will be OK
  if (str.length > 4093) {
    console.log('Warning! Session cookie is too large (', str.length, '), data:', JSON.stringify(body));
  }
  return str;
}

/**
 * Try getting a session from a cookie.
 * @private
 */

function tryGetSession (cookies, name, opts) {
  var str = cookies.get(name, opts)

  if (!str) {
    return undefined
  }

  debug('parse %s', str)

  try {
    return Session.deserialize(str, opts)
  } catch (err) {
    return undefined
  }
}
