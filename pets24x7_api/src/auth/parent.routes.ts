// Pet Parent auth — WA-OTP signup & login.
//   POST /api/parent/request-otp { phone, name?, email? }
//   POST /api/parent/verify     { phone, code }   → JWT cookie

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

import { prisma } from '../db.js';
import { issueOtp, verifyOtp } from '../whatsapp/otp.js';
import { setAuthCookie } from './jwt.js';
import { normalizePhone } from '../shared/phone.js';
import { asyncHandler } from '../shared/async-handler.js';
import { BadRequestError } from '../shared/errors.js';

export const parentAuthRouter = Router();

const otpLimiter = rateLimit({ windowMs: 60_000, max: 4, standardHeaders: true });

// ----- Request OTP -----
const RequestOtpBody = z.object({
  phone: z.string().min(6),
  name: z.string().min(2).max(80).optional(),
  email: z.string().email().optional(),
  city: z.string().max(80).optional(),
  country: z.enum(['IN', 'US']).optional(),
});

parentAuthRouter.post(
  '/request-otp',
  otpLimiter,
  asyncHandler(async (req, res) => {
    const body = RequestOtpBody.parse(req.body);
    const phone = normalizePhone(body.phone, body.country ?? 'IN');

    // Upsert a "shell" parent so the next step has a row to attach pets to.
    await prisma.petParent.upsert({
      where: { phone },
      update: {
        ...(body.name && { name: body.name }),
        ...(body.email && { email: body.email }),
        ...(body.city && { city: body.city }),
        ...(body.country && { country: body.country }),
      },
      create: {
        phone,
        name: body.name ?? 'Pet Parent',
        ...(body.email && { email: body.email }),
        ...(body.city && { city: body.city }),
        ...(body.country && { country: body.country }),
      },
    });

    await issueOtp(phone, 'PARENT_SIGNUP', { ip: req.ip, ua: req.headers['user-agent'] });
    res.json({ ok: true, phone });
  }),
);

// ----- Verify OTP -----
const VerifyBody = z.object({
  phone: z.string().min(6),
  code: z.string().length(6),
});

parentAuthRouter.post(
  '/verify',
  asyncHandler(async (req, res) => {
    const { phone, code } = VerifyBody.parse(req.body);
    const ok = await verifyOtp(phone, code, 'PARENT_SIGNUP');
    if (!ok) throw new BadRequestError('Incorrect code');

    const parent = await prisma.petParent.findUnique({ where: { phone: normalizePhone(phone) } });
    if (!parent) throw new BadRequestError('Account not found — please request OTP again');

    setAuthCookie(res, { sub: parent.id, role: 'pet_parent' });
    res.json({ ok: true, parent: { id: parent.id, name: parent.name, phone: parent.phone, email: parent.email } });
  }),
);
