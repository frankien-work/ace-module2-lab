/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

function hasMaliciousContent (data: string): boolean {
  let decoded = data
  try {
    decoded = decoded
      .replace(/\\u\{([0-9a-fA-F]+)\}/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
      .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
      .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
  } catch {
    return true
  }

  const forbiddenPatterns = [
    /constructor/i,
    /__proto__/i,
    /prototype/i,
    /getPrototypeOf/i,
    /setPrototypeOf/i,
    /defineProperty/i,
    /defineProperties/i,
    /process/i,
    /mainModule/i,
    /child_process/i,
    /require/i,
    /import/i,
    /\bFunction\b/i,
    /\beval\b/i,
    /\bexec\b/i,
    /\bexecSync\b/i,
    /\bspawn\b/i,
    /\bspawnSync\b/i,
    /\bfork\b/i,
    /\bglobal\b/i,
    /\bglobalThis\b/i,
    /\bthis\b/i,
    /\bfs\b/i,
    /fromCharCode/i,
    /fromCodePoint/i
  ]

  return forbiddenPatterns.some((pattern) => pattern.test(decoded))
}

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      if (typeof orderLinesData !== 'string' || hasMaliciousContent(orderLinesData)) {
        res.status(400)
        next(new Error('Invalid order lines data'))
        return
      }
      try {
        const sandbox = { safeEval, orderLinesData }
        vm.createContext(sandbox)
        const origFunctionConstructor = Function.prototype.constructor
        try {
          // @ts-expect-error override constructor for sandboxing
          Function.prototype.constructor = function () {
            throw new Error('Code execution disallowed')
          }
          vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        } finally {
          Function.prototype.constructor = origFunctionConstructor
        }
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
