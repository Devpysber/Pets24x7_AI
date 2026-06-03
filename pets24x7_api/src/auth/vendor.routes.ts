// Vendor auth — WA-OTP with mandatory phone-match against existing static listings.
//   POST /api/vendor/request-otp { phone }
//      → 200 { matches: [...] }   (phone matched ≥ 1 listing, OTP sent)
//      → 200 { matches: [], hint: "no_match" }   (no matches, do NOT send OTP)
//   POST /api/vendor/verify     { phone, code, listingId, businessName, email? }
//      → JWT cookie + Vendor row created (status PENDING, awaiting admin approve)

import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

import { prisma } from '../db.js';
import { issueOtp, verifyOtp } from '../whatsapp/otp.js';
import { setAuthCookie } from './jwt.js';
import { findListingByPhone, getListingById } from '../listings/index.js';
import { normalizePhone } from '../shared/phone.js';
import { asyncHandler } from '../shared/async-handler.js';
import { BadRequestError, ConflictError } from '../shared/errors.js';

export const vendorAuthRouter = Router();

const otpLimiter = rateLimit({ windowMs: 60_000, max: 4, standardHeaders: true });

// ----- Step 1: phone match + OTP -----
const RequestOtpBody = z.object({
  phone: z.string().min(6),
  country: z.enum(['IN', 'US']).optional(),
});

vendorAuthRouter.post(
  '/request-otp',
  otpLimiter,
  asyncHandler(async (req, res) => {
    const body = RequestOtpBody.parse(req.body);
    const phone = normalizePhone(body.phone, body.country ?? 'IN');
    const matches = findListingByPhone(phone);

    if (matches.length === 0) {
      // Do NOT send OTP — vendor isn't in our scrape. Surface a CTA to request
      // a new listing (Phase 2: an admin-reviewed listing request flow).
      return res.json({ ok: true, phone, matches: [], hint: 'no_match' });
    }

    await issueOtp(phone, 'VENDOR_CLAIM', { ip: req.ip, ua: req.headers['user-agent'] });
    res.json({
      ok: true,
      phone,
      matches: matches.slice(0, 5).map((m) => ({
        id: m.id,
        name: m.name,
        category: m.category,
        city: m.city,
        state: m.state ?? '',
        country: m.country,
        address: m.address ?? '',
        rating: m.rating,
        review_count: m.review_count,
        url: `/${(m.country || 'in').toLowerCase()}/${m.city_slug}/${m.id}/`,
      })),
    });
  }),
);

// ----- Step 2: verify + claim a specific listing -----
const VerifyBody = z.object({
  phone: z.string().min(6),
  code: z.string().length(6),
  listingId: z.string().min(3),
  businessName: z.string().min(2).max(120).optional(),
  email: z.string().email().optional(),
});

vendorAuthRouter.post(
  '/verify',
  asyncHandler(async (req, res) => {
    const body = VerifyBody.parse(req.body);
    const phone = normalizePhone(body.phone);

    // Listing must exist in our static index
    const listing = getListingById(body.listingId);
    if (!listing) throw new BadRequestError('Listing not found');

    // ...and its phone must match the requesting phone (enforce ownership)
    const matches = findListingByPhone(phone);
    if (!matches.some((m) => m.id === listing.id)) {
      throw new BadRequestError('This listing is not registered to your WhatsApp number');
    }

    // Listing can only be claimed once
    const alreadyClaimed = await prisma.vendor.findUnique({ where: { listingId: listing.id } });
    if (alreadyClaimed && alreadyClaimed.phone !== phone) {
      throw new ConflictError('This listing has already been claimed');
    }

    const ok = await verifyOtp(phone, body.code, 'VENDOR_CLAIM');
    if (!ok) throw new BadRequestError('Incorrect code');

    const now = new Date();
    const vendor = await prisma.vendor.upsert({
      where: { phone },
      update: {
        listingId: listing.id,
        businessName: body.businessName ?? listing.name,
        email: body.email ?? null,
        city: listing.city,
        country: listing.country,
        category: listing.category,
        status: 'PENDING',
        claimedAt: now,
      },
      create: {
        phone,
        listingId: listing.id,
        businessName: body.businessName ?? listing.name,
        email: body.email ?? null,
        city: listing.city,
        country: listing.country,
        category: listing.category,
        status: 'PENDING',
        claimedAt: now,
      },
    });

    await prisma.auditLog.create({
      data: {
        actorType: 'VENDOR',
        actorId: vendor.id,
        action: 'vendor.claim',
        meta: { listingId: listing.id, listingName: listing.name },
        ipAddress: req.ip,
      },
    });

    setAuthCookie(res, { sub: vendor.id, role: 'vendor' });
    res.json({
      ok: true,
      vendor: {
        id: vendor.id,
        status: vendor.status,
        businessName: vendor.businessName,
        listing: {
          id: listing.id,
          name: listing.name,
          city: listing.city,
          category: listing.category,
          rating: listing.rating,
          review_count: listing.review_count,
        },
      },
    });
  }),
);
