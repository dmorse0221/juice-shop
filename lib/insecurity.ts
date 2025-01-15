/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'fs'
import crypto from 'crypto'
import { type Request, type Response, type NextFunction } from 'express'
import { type UserModel } from 'models/user'
import expressJwt from 'express-jwt'
import jwt from 'jsonwebtoken'
import jws from 'jws'
import sanitizeHtmlLib from 'sanitize-html'
import sanitizeFilenameLib from 'sanitize-filename'
import * as utils from './utils'

/* jslint node: true */
// eslint-disable-next-line @typescript-eslint/prefer-ts-expect-error
// @ts-expect-error FIXME no typescript definitions for z85 :(
import * as z85 from 'z85'

const loadKey = (envVar: string, fallbackPath: string) => {
  if (process.env[envVar]) {
    return process.env[envVar]
  }
  try {
    return fs.readFileSync(fallbackPath, 'utf8')
  } catch (err) {
    console.error(`Error: Could not load key from ${fallbackPath}. Please configure ${envVar} environment variable.`)
    process.exit(1)
  }
}

// Load keys from environment variables or files
const loadKeyFromEnv = (envVar: string, fallbackPath: string) => {
  if (process.env[envVar]) {
    return process.env[envVar]
  }
  try {
    return fs.readFileSync(fallbackPath, 'utf8')
  } catch (err) {
    console.error(`Error: Could not load key from ${fallbackPath}. Please configure ${envVar} environment variable.`)
    process.exit(1)
  }
}

export const publicKey = loadKeyFromEnv('JWT_PUBLIC_KEY', 'encryptionkeys/jwt.pub')
const privateKey = loadKeyFromEnv('JWT_PRIVATE_KEY', 'encryptionkeys/jwt.key')

// Validate keys are properly loaded
if (!publicKey || !privateKey) {
  console.error('Error: JWT keys not properly configured')
  process.exit(1)
}

interface ResponseWithUser {
  status: string
  data: UserModel
  iat: number
  exp: number
  bid: number
}

interface IAuthenticatedUsers {
  tokenMap: Record<string, ResponseWithUser>
  idMap: Record<string, string>
  put: (token: string, user: ResponseWithUser) => void
  get: (token: string) => ResponseWithUser | undefined
  tokenOf: (user: UserModel) => string | undefined
  from: (req: Request) => ResponseWithUser | undefined
  updateFrom: (req: Request, user: ResponseWithUser) => any
}

export const hash = (data: string) => {
  const algorithm = process.env.HASH_ALGORITHM ?? 'sha256'
  return crypto.createHash(algorithm).update(data).digest('hex')
}
export const hmac = (data: string) => {
  const secret = process.env.HMAC_SECRET
  if (!secret) {
    throw new Error('HMAC_SECRET environment variable must be configured')
  }
  return crypto.createHmac('sha256', secret).update(data).digest('hex')
}

export const cutOffPoisonNullByte = (str: string) => {
  const nullByte = '%00'
  if (utils.contains(str, nullByte)) {
    return str.substring(0, str.indexOf(nullByte))
  }
  return str
}

export const isAuthorized = () => expressJwt({
  secret: publicKey,
  algorithms: ['RS256'],
  requestProperty: 'user',
  getToken: (req: Request) => {
    if (req.headers.authorization?.split(' ')[0] === 'Bearer') {
      return req.headers.authorization.split(' ')[1]
    }
    return null
  }
})

export const denyAll = () => (req: Request, res: Response) => {
  res.status(401).json({ status: 'error', message: 'Unauthorized' })
}

export const authorize = (user = {}) => jwt.sign(
  user,
  privateKey,
  {
    expiresIn: process.env.JWT_EXPIRY ?? '1h',
    algorithm: 'RS256',
    issuer: process.env.JWT_ISSUER ?? undefined,
    audience: process.env.JWT_AUDIENCE ?? undefined,
    notBefore: '0'
  }
)

export const verify = (token: string) => {
  if (!process.env.JWT_ISSUER || !process.env.JWT_AUDIENCE) {
    throw new Error('JWT configuration is incomplete. Required environment variables: JWT_ISSUER, JWT_AUDIENCE')
  }
  try {
    return jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      issuer: process.env.JWT_ISSUER,
      audience: process.env.JWT_AUDIENCE
    })
  } catch (err) {
    return false
  }
}
export const decode = (token: string) => { return jws.decode(token)?.payload }

export const sanitizeHtml = (html: string) => sanitizeHtmlLib(html)
export const sanitizeLegacy = (input = '') => input.replace(/<(?:\w+)\W+?[\w]/gi, '')
export const sanitizeFilename = (filename: string) => sanitizeFilenameLib(filename)
export const sanitizeSecure = (html: string): string => {
  const sanitized = sanitizeHtml(html)
  if (sanitized === html) {
    return html
  } else {
    return sanitizeSecure(sanitized)
  }
}

export const authenticatedUsers: IAuthenticatedUsers = {
  tokenMap: {},
  idMap: {},
  put: function (token: string, user: ResponseWithUser) {
    this.tokenMap[token] = user
    this.idMap[user.data.id] = token
  },
  get: function (token: string) {
    return token ? this.tokenMap[utils.unquote(token)] : undefined
  },
  tokenOf: function (user: UserModel) {
    return user ? this.idMap[user.id] : undefined
  },
  from: function (req: Request) {
    const token = utils.jwtFrom(req)
    return token ? this.get(token) : undefined
  },
  updateFrom: function (req: Request, user: ResponseWithUser) {
    const token = utils.jwtFrom(req)
    this.put(token, user)
  }
}

export const userEmailFrom = ({ headers }: any) => {
  return headers ? headers['x-user-email'] : undefined
}

export const generateCoupon = (discount: number, date = new Date()) => {
  const coupon = utils.toMMMYY(date) + '-' + discount
  return z85.encode(coupon)
}

export const discountFromCoupon = (coupon: string) => {
  if (coupon) {
    const decoded = z85.decode(coupon)
    if (decoded && (hasValidFormat(decoded.toString()) != null)) {
      const parts = decoded.toString().split('-')
      const validity = parts[0]
      if (utils.toMMMYY(new Date()) === validity) {
        const discount = parts[1]
        return parseInt(discount)
      }
    }
  }
  return undefined
}

function hasValidFormat (coupon: string) {
  return coupon.match(/(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[0-9]{2}-[0-9]{2}/)
}

// vuln-code-snippet start redirectCryptoCurrencyChallenge redirectChallenge
export const redirectAllowlist = new Set(
  (process.env.ALLOWED_REDIRECT_HOSTS ?? '').split(',').filter(Boolean)
)

export const isRedirectAllowed = (url: string) => {
  try {
    const parsedUrl = new URL(url)
    const allowedDomains = Array.from(redirectAllowlist).map(domain => {
      try {
        return new URL(domain).hostname
      } catch {
        return domain
      }
    })
    return allowedDomains.some(domain => parsedUrl.hostname === domain)
  } catch {
    return false
  }
}
// vuln-code-snippet end redirectCryptoCurrencyChallenge redirectChallenge

export const roles = {
  customer: 'customer',
  deluxe: 'deluxe',
  accounting: 'accounting',
  admin: 'admin'
}

export const deluxeToken = (email: string) => {
  if (!process.env.HMAC_SECRET) {
    throw new Error('HMAC_SECRET environment variable must be configured')
  }
  const hmac = crypto.createHmac('sha256', process.env.HMAC_SECRET)
  return hmac.update(email + roles.deluxe).digest('hex')
}

export const isAccounting = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
    if (decodedToken?.data?.role === roles.accounting) {
      next()
    } else {
      res.status(403).json({ error: 'Malicious activity detected' })
    }
  }
}

export const isDeluxe = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.deluxe && decodedToken?.data?.deluxeToken && decodedToken?.data?.deluxeToken === deluxeToken(decodedToken?.data?.email)
}

export const isCustomer = (req: Request) => {
  const decodedToken = verify(utils.jwtFrom(req)) && decode(utils.jwtFrom(req))
  return decodedToken?.data?.role === roles.customer
}

export const appendUserId = () => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      req.body.UserId = authenticatedUsers.tokenMap[utils.jwtFrom(req)].data.id
      next()
    } catch (error: any) {
      res.status(401).json({ status: 'error', message: error })
    }
  }
}

export const updateAuthenticatedUsers = () => (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token || utils.jwtFrom(req)
  if (token) {
    jwt.verify(token, publicKey, (err: Error | null, decoded: any) => {
      if (err === null) {
        if (authenticatedUsers.get(token) === undefined) {
          authenticatedUsers.put(token, decoded)
          res.cookie('token', token)
        }
      }
    })
  }
  next()
}
