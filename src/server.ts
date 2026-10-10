import cors from 'cors';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import express, { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { config } from './config.js';
import { xcode } from './xcode-client.js';
import { assertActionSucceeded } from './action-response.js';
import { mergeRedemptionHistory } from './redemption-history.js';
import { NotificationStore } from './notification-store.js';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ImportArchive } from './import-archive.js';

const localDataDirectory = process.env.EDUVO_DATA_DIR || fileURLToPath(new URL('../data/', import.meta.url));
const notificationStore = new NotificationStore(resolve(localDataDirectory, 'notifications.json'));
const importArchive = new ImportArchive(resolve(localDataDirectory, 'import-archive.json'));

async function memberNotificationOperation(endpoint: string, payload: any) {
  const phone = String(payload?.PhoneNumber || '').trim();
  if (!validPhone(phone)) throw Object.assign(new Error('A valid member phone number is required.'), { status: 400 });
  if (endpoint === 'MemberNotification/GetNotificationsFilterMember') {
    const local = await notificationStore.list(phone);
    const remote = await xcode.post(endpoint, payload).catch(error => {
      console.warn('Provider notification inbox unavailable; serving the local inbox.');
      if (!local.length) throw error;
      return [];
    });
    return [...recordList(remote), ...local];
  }
  const id = String(payload?.NotificationId || payload?.Notification_Id || '');
  if (id.startsWith('local-notification-')) {
    return endpoint === 'MemberNotification/GetNotificationsDetails'
      ? notificationStore.detail(phone, id) : notificationStore.read(phone, id);
  }
  if (endpoint === 'MemberNotification/UserReadAllNotification') {
    const result = await xcode.post(endpoint, payload);
    assertActionSucceeded(result);
    await notificationStore.read(phone);
    return result;
  }
  return xcode.post(endpoint, payload);
}


const app = express();
app.use(cors({ origin: config.clientOrigins, credentials: false }));
app.use(express.json({ limit: '3mb' }));

type MemberSession = { phoneNumber?: string; email?: string; merchantId?: string; role: 'member' | 'merchant' | 'admin' | 'web-service' | 'admin-service' };
type ResetOtp = { code: string; expiresAt: number };
type LoginOtpDevice = { otpDeviceId: string; targetDeviceId: string; otp: string; attempts: number; expiresAt: number };
type QrGrant = { purpose: 'member-scan' | 'reward-scan'; phoneNumber: string; rewardId?: string; kind?: string; expiresAt: number };
type CatalogProduct = { id: string; name: string; description: string; category: string; price: number; active: boolean };
type CheckoutLine = { productId: string; quantity: number };
const resetOtps = new Map<string, ResetOtp>();
const emailOtps = new Map<string, ResetOtp>();
const loginOtpDevices = new Map<string, LoginOtpDevice>();
const qrGrants = new Map<string, QrGrant>();
const checkoutInFlight = new Set<string>();
const validPhone = (value: unknown) => typeof value === 'string' && /^\+?\d{8,15}$/.test(value.trim());
const validEmail = (value: unknown) => typeof value === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());

async function requireEligibleReward(phoneNumber: string, rewardId: string, voucher = false) {
  const result = voucher
    ? await xcode.post('MemberVoucher/GetVoucherById', { RewardId: rewardId, PhoneNumber: phoneNumber })
    : await xcode.post('MemberReward/FindReward', { RewardId: rewardId });
  const reward = firstRecord(result);
  if (reward.RewardId !== rewardId) throw Object.assign(new Error('This reward or voucher could not be found.'), { status: 400 });
  const expiry = reward.ExpireDate ? new Date(String(reward.ExpireDate)).getTime() : undefined;
  if ((reward.Status && String(reward.Status).toLowerCase() !== 'active') || (expiry !== undefined && (!Number.isFinite(expiry) || expiry <= Date.now()))) {
    throw Object.assign(new Error('This reward or voucher is expired or unavailable.'), { status: 400 });
  }
  const wallet = firstRecord(await xcode.post('MemberWallet/MemberGetWalletDetails', { PhoneNumber: phoneNumber }));
  if (Number(reward.Point || 0) > Number(wallet.Point || 0)) throw Object.assign(new Error('The member does not have enough points for this reward.'), { status: 400 });
}

async function readCatalog(): Promise<CatalogProduct[]> {
  const response = await xcode.get('MemberMenu/GetMenuStatusActive');
  return recordList(response).map(item => ({
    id: String(item.MenuId || ''),
    name: String(item.ItemName || 'Menu item'),
    description: String(item.ItemDescription || ''),
    category: String(item.Category || 'Menu'),
    price: Number(item.Price || 0),
    active: String(item.Status || 'Active').toLowerCase() === 'active',
  })).filter(product => product.active && product.id && Number.isFinite(product.price) && product.price >= 0);
}

function issueMemberSession(data: Omit<MemberSession, 'role'>) {
  return jwt.sign({ ...data, role: 'member' }, config.appJwtSecret, { expiresIn: '8h' });
}

function issueMerchantSession(merchantId: string) {
  return jwt.sign({ merchantId, role: 'merchant' }, config.appJwtSecret, { expiresIn: '10h' });
}

function issueQrToken(grant: Omit<QrGrant, 'expiresAt'>): string {
  const now = Date.now();
  if (grant.purpose === 'member-scan') {
    const phonePart = `${grant.phoneNumber.startsWith('+') ? 'p' : 'n'}${grant.phoneNumber.replace(/\D/g, '')}`;
    const expiresAtMinute = Math.ceil((now + 5 * 60 * 1000) / 60_000).toString(36);
    const unsigned = `m_${phonePart}_${expiresAtMinute}`;
    const signature = createHmac('sha256', config.appJwtSecret).update(unsigned).digest('base64url').slice(0, 12);
    return `${unsigned}_${signature}`;
  }
  for (const [key, value] of qrGrants) if (value.expiresAt <= now) qrGrants.delete(key);
  let token = randomBytes(16).toString('base64url');
  while (qrGrants.has(token)) token = randomBytes(16).toString('base64url');
  qrGrants.set(token, { ...grant, expiresAt: now + 5 * 60 * 1000 });
  return token;
}

function verifyQrToken(token: string, purpose: 'member-scan' | 'reward-scan', phoneNumber = '', rewardId = '') {
  let claims: Record<string, unknown>;
  if (purpose === 'member-scan' && token.startsWith('m_')) {
    const parts = token.split('_');
    const unsigned = parts.slice(0, 3).join('_');
    const expectedSignature = createHmac('sha256', config.appJwtSecret).update(unsigned).digest('base64url').slice(0, 12);
    // Base64url signatures may themselves contain underscores.
    const suppliedSignature = parts.slice(3).join('_');
    const signatureMatches = suppliedSignature.length === expectedSignature.length && timingSafeEqual(Buffer.from(suppliedSignature), Buffer.from(expectedSignature));
    const expiresAt = Number.parseInt(parts[2] || '', 36) * 60_000;
    const phonePart = parts[1] || '';
    const resolvedPhone = `${phonePart.startsWith('p') ? '+' : ''}${phonePart.slice(1)}`;
    if (!/^m_[pn]\d{8,15}_[a-z0-9]+_[A-Za-z0-9_-]{12}$/.test(token) || !signatureMatches || !validPhone(resolvedPhone) || !Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      throw Object.assign(new Error('This QR code is invalid or has expired. Refresh the member QR and scan it again.'), { status: 400 });
    }
    claims = { purpose: 'member-scan', phoneNumber: resolvedPhone };
  } else {
    const grant = qrGrants.get(token);
    if (grant) {
    if (grant.expiresAt <= Date.now()) {
      qrGrants.delete(token);
      throw Object.assign(new Error('This QR code is invalid or has expired.'), { status: 400 });
    }
    claims = grant as unknown as Record<string, unknown>;
    } else {
      // Keep accepting previously generated signed QRs during the transition.
      try {
        claims = jwt.verify(token, config.appJwtSecret) as Record<string, unknown>;
      } catch {
        throw Object.assign(new Error('This QR code is invalid or has expired. Refresh the member QR and scan it again.'), { status: 400 });
      }
    }
  }
  if (claims.purpose !== purpose || (phoneNumber && String(claims.phoneNumber || '') !== phoneNumber)) {
    throw Object.assign(new Error('This QR code does not match the selected member.'), { status: 400 });
  }
  if (rewardId && String(claims.rewardId || '') !== rewardId) {
    throw Object.assign(new Error('This QR code does not match the selected reward.'), { status: 400 });
  }
  return claims;
}

function requireSession(req: Request, res: Response, next: NextFunction) {
  const token = req.header('authorization')?.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ message: 'Missing application session token.' });
  try {
    res.locals.session = jwt.verify(token, config.appJwtSecret) as MemberSession;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired application session.' });
  }
}

function requireMerchant(req: Request, res: Response, next: NextFunction) {
  requireSession(req, res, () => {
    const session = res.locals.session as MemberSession;
    if (session.role !== 'merchant' || !session.merchantId) return res.status(403).json({ message: 'Merchant sign-in is required.' });
    next();
  });
}

function hasMemberRecord(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  if (!value || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;
  return Boolean(record.PhoneNumber || record.phoneNumber || record.Email || record.email || record.Id || record.id);
}

function isMemberNotFoundError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const response = 'response' in error
    ? (error as { response?: { status?: number; data?: unknown } }).response
    : undefined;
  const body = response?.data;
  const message = typeof body === 'string'
    ? body
    : body && typeof body === 'object'
      ? String((body as Record<string, unknown>).message || (body as Record<string, unknown>).Message || (body as Record<string, unknown>).error || '')
      : '';
  return response?.status === 404 || /member\s+not\s+found/i.test(message);
}

async function findOptionalMember(path: string, body: unknown): Promise<unknown> {
  try {
    return await xcode.post(path, body);
  } catch (error) {
    if (isMemberNotFoundError(error)) return null;
    throw error;
  }
}

function withoutPassword(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(withoutPassword);
  if (!value || typeof value !== 'object') return value;
  const { Password: _password, password: _passwordLower, ...safeValue } = value as Record<string, unknown>;
  return safeValue;
}

// Restricted server-to-server adapter for the MVC member portal. Provider
// credentials and tokens remain here, not in the website or its browser.
const webGetEndpoints = new Set([
  'MemberReward/GetRewards', 'MemberVoucher/GetAllVoucher',
  'ManageHighlight/UserGetAllHighlight', 'ManageOutlets/GetAllOutlets',
]);
const webPostEndpoints = new Set([
  'ManageMember/FindMemberByEmail', 'ManageMember/FindMemberByPhone',
  'MemberAccount/MemberResetPassword', 'MemberAccount/RegisterOtp', 'MemberAccount/RequestOTP',
  'MemberDetails/GetMemberDetails', 'MemberLogin/CheckEmailPassword',
  'MemberLogin/MemberMobileLoginGetProfile', 'MemberLogin/RegisterMember',
  'MemberWallet/CheckReffererCodeValid', 'MemberAccount/GenerateMailOTP', 'MemberAccount/UpdateAccountVerify',
  'FeedBack/CreateFeedback', 'FeedBack/GetFeedbackListFilterUser',
  'History/GetAllRecordByPhoneNumber', 'History/GetAssignPointRecordByPhoneNumber',
  'History/GetAssignStampRecordByPhoneNumber', 'History/GetPaymentRecordByPhoneNumber',
  'History/GetRedeemRewardRecordByPhoneNumber', 'History/GetRedeemVoucherRecordByPhoneNumber',
  'History/GetStampRecordByPhoneNumber', 'History/GetTopUpRecordByPhoneNumber',
  'MerchantTransactionHistories/GetAllRewardsRecordsFilterByMember',
  'MerchantTransactionHistories/GetAllVoucherRecordsFilterByMember',
  'MemberAccount/GetMemberDownlineList', 'MemberAccount/GetMemberReward',
  'MemberAccount/GetMemberStampList', 'MemberAccount/GetMemberStampUsedRecord',
  'MemberAccount/GetMemberVoucherHistories', 'MemberAccount/GetSpendRecords',
  'MemberAccount/GetTopUpRecordDetails', 'MemberAccount/MemberEditProfile',
  'MemberAccount/UpdateAccountStatusDeactive', 'MemberNotification/GetNotificationsDetails',
  'MemberNotification/GetNotificationsFilterMember', 'MemberNotification/UserReadNotification',
  'MemberNotification/UserReadAllNotification', 'MemberReward/FindReward',
  'MemberVoucher/GetVoucherById', 'MemberVoucher/GetVoucherByPhone', 'MemberWallet/MemberGetWalletDetails',
]);
app.post('/web/member-api', requireSession, async (req, res, next) => {
  if ((res.locals.session as MemberSession).role !== 'web-service') {
    return res.status(403).json({ message: 'Website service authorization is required.' });
  }
  const { endpoint, method, payload } = req.body;
  if (typeof endpoint !== 'string' ||
      !(method === 'GET' ? webGetEndpoints.has(endpoint) : method === 'POST' && webPostEndpoints.has(endpoint))) {
    return res.status(400).json({ message: 'This member operation is not supported.' });
  }
  try {
    const result = method === 'GET' ? await xcode.get(endpoint)
      : endpoint.startsWith('MemberNotification/') ? await memberNotificationOperation(endpoint, payload ?? {})
      : await xcode.post(endpoint, payload ?? {});
    if (method === 'POST' && new Set([
      'MemberLogin/RegisterMember', 'MemberAccount/MemberResetPassword',
      'MemberAccount/UpdateAccountVerify', 'MemberAccount/MemberEditProfile',
      'MemberAccount/UpdateAccountStatusDeactive', 'FeedBack/CreateFeedback',
      'MemberNotification/UserReadNotification', 'MemberNotification/UserReadAllNotification',
    ]).has(endpoint)) assertActionSucceeded(result);
    res.setHeader('Cache-Control', 'no-store');
    return res.json(withoutPassword(result));
  } catch (error) { next(error); }
});

function firstRecord(value: unknown): Record<string, unknown> {
  const record = Array.isArray(value) ? value[0] : value;
  return record && typeof record === 'object' ? record as Record<string, unknown> : {};
}

function recordList(value: unknown): Record<string, unknown>[] {
  if (Array.isArray(value)) return value.filter(item => item && typeof item === 'object') as Record<string, unknown>[];
  if (!value || typeof value !== 'object') return [];
  const record = value as Record<string, unknown>;
  for (const key of ['data', 'Data', 'items', 'Items', 'result', 'Result']) {
    if (Array.isArray(record[key])) return record[key] as Record<string, unknown>[];
  }
  return [record];
}

const wait = (milliseconds: number) => new Promise(resolve => setTimeout(resolve, milliseconds));

async function confirmSpendRecord(phoneNumber: string, referenceNumber: string): Promise<Record<string, unknown> | undefined> {
  for (const delay of [0, 250, 600, 1200]) {
    if (delay) await wait(delay);
    const history = await xcode.post('MerchantTransactionHistories/GetMemberSpendRecords', { PhoneNumber: phoneNumber });
    const match = recordList(history).find(item => String(item.ReferenceNumber || '') === referenceNumber && /paid|success/i.test(String(item.Status || item.IsPaid || '')));
    if (match) return match;
  }
  return undefined;
}

function extractOtp(value: unknown): string {
  if (typeof value === 'string') return /^\d{4,10}$/.test(value.replace(/"/g, '').trim()) ? value.replace(/"/g, '').trim() : '';
  return String(firstRecord(value).OTP || '');
}

function memberPhone(req: Request, res: Response): string | undefined {
  const phoneNumber = req.params.phoneNumber;
  const session = res.locals.session as MemberSession;
  if (!session.phoneNumber || session.phoneNumber !== phoneNumber) {
    res.status(403).json({ message: 'You can only access your own member account.' });
    return undefined;
  }
  return phoneNumber;
}

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.post('/admin/notifications/:audience', requireSession, async (req, res, next) => {
  if ((res.locals.session as MemberSession).role !== 'admin-service') return res.status(403).json({ message: 'Admin service authorization is required.' });
  try {
    const audience = String(req.params.audience);
    if (!['all', 'member'].includes(audience)) return res.status(400).json({ message: 'Choose a valid audience.' });
    const phone = audience === 'member' ? String(req.body.PhoneNumber || '').trim() : null;
    res.json(await notificationStore.send(phone, String(req.body.NotificationHeader || req.body.Title || ''), String(req.body.NotificationBody || req.body.Text || ''), 'admin'));
  } catch (error) { next(error); }
});

app.post('/admin/imports/:kind', requireSession, async (req, res, next) => {
  if ((res.locals.session as MemberSession).role !== 'admin-service') return res.status(403).json({ message: 'Admin service authorization is required.' });
  try { res.json(await importArchive.save(String(req.params.kind), req.body)); }
  catch (error) { next(error); }
});
app.get('/admin/imports', requireSession, async (req, res, next) => {
  if ((res.locals.session as MemberSession).role !== 'admin-service') return res.status(403).json({ message: 'Admin service authorization is required.' });
  try { res.json(await importArchive.list(typeof req.query.kind === 'string' ? req.query.kind : undefined)); }
  catch (error) { next(error); }
});

app.post('/pos/login', async (req, res, next) => {
  try {
    const merchantId = String(req.body.merchantId || '').trim();
    const password = String(req.body.password || '');
    if (!merchantId || !password) return res.status(400).json({ message: 'Enter the merchant ID and password.' });
    const profile = await xcode.post('MerchantLogin/MerchantPosMachineLoginGetProfile', { MerchantId: merchantId, Password: password });
    if (!Object.keys(firstRecord(profile)).length) return res.status(401).json({ message: 'The merchant ID or password is incorrect.' });
    res.json({ profile: withoutPassword(profile), sessionToken: issueMerchantSession(merchantId), merchantId });
  } catch (error) { next(error); }
});

app.get('/pos/session', requireMerchant, (_req, res) => {
  const session = res.locals.session as MemberSession;
  res.json({ valid: true, merchantId: session.merchantId });
});

app.get('/pos/catalog', requireMerchant, async (_req, res, next) => {
  try {
    res.json(await readCatalog());
  } catch (error) { next(error); }
});

app.post('/pos/member/scan', requireMerchant, async (req, res, next) => {
  try {
    let phone = String(req.body.phone || '').trim();
    const verificationToken = String(req.body.verificationToken || '').trim();
    if (!phone && verificationToken) {
      const claims = verifyQrToken(verificationToken, 'member-scan');
      phone = String(claims.phoneNumber || '').trim();
    }
    if (!validPhone(phone)) return res.status(400).json({ message: 'Enter a valid member phone number.' });
    if (verificationToken) verifyQrToken(verificationToken, 'member-scan', phone);
    const [member, wallet] = await Promise.all([
      xcode.post('MerchantScanMemberInfo/ScanGetMemberDetails', { Phone: phone }),
      xcode.post('MemberWallet/MemberGetWalletDetails', { PhoneNumber: phone }),
    ]);
    const balances = firstRecord(wallet);
    res.json(withoutPassword({
      ...firstRecord(member),
      PhoneNumber: phone,
      Balance: balances.Balance,
      Point: balances.Point,
      TotalStamp: balances.TotalStamp,
      PointBonus: balances.PointBonus,
      Tier: balances.Tier,
      ExpireDate: balances.ExpireDate,
    }));
  } catch (error) { next(error); }
});

app.post('/pos/member/register', requireMerchant, async (req, res, next) => {
  try {
    const name = String(req.body.Name || '').trim();
    const email = String(req.body.Email || '').trim();
    const phoneNumber = String(req.body.PhoneNumber || '').trim();
    if (!name || !validEmail(email) || !validPhone(phoneNumber)) {
      return res.status(400).json({ message: 'Enter the member name, a valid email, and a valid phone number.' });
    }
    const member = {
      Id: 0,
      UserId: '',
      Name: name,
      Email: email,
      PhoneNumber: phoneNumber,
      BirthDate: String(req.body.BirthDate || ''),
      ReferralCode: '',
      ReferralBy: String(req.body.ReferralBy || ''),
      Password: String(req.body.Password || ''),
      Tier: 'Member',
      Image: '',
      ImageByte: '',
      FirstLogin: 'True',
      EmailSubcribe: 'active',
      NotificationStatus: 'true',
      AccountStatus: 'active',
      RegisterTime: new Date().toISOString(),
      DeviceId: '',
      DeliveryStatus: '',
      EmailVerified: false,
      PhoneVerified: false
    };
    res.json(await xcode.post('MerchantRegisterMember/RegisterMember', member));
  } catch (error) { next(error); }
});

const posActionEndpoints: Record<string, { endpoint: string; merchantField?: string }> = {
  'cash-spend': { endpoint: 'MerchantSpend/CashSpend', merchantField: 'MerchantId' },
  'wallet-spend': { endpoint: 'MerchantSpend/WalletSpend', merchantField: 'MerchantId' },
  topup: { endpoint: 'MerchantTopup/CreateTopUpWallet', merchantField: 'MerchantId' },
  'update-topup': { endpoint: 'MerchantTopup/UpdateTopUpWallet' },
  points: { endpoint: 'ManagePoint/AssignPoint', merchantField: 'MerchantId' },
  'assign-stamp': { endpoint: 'MerchantStamp/AssignStamp', merchantField: 'Merchant_Id' },
  'check-stamp': { endpoint: 'MerchantStamp/CheckMemberStampList' },
  'use-stamp': { endpoint: 'MerchantStamp/UseStamp', merchantField: 'Merchant_Id' },
  'redeem-reward': { endpoint: 'MerchantScanReward/ScanReward', merchantField: 'Merchant_Id' },
  'void-spend': { endpoint: 'MerchantSpend/VoidSpend' },
  'void-topup': { endpoint: 'MerchantTransactionHistories/VoidTopupRecord' }
};

app.post('/pos/actions/:action', requireMerchant, async (req, res, next) => {
  try {
    const action = posActionEndpoints[String(req.params.action)];
    if (!action) return res.status(404).json({ message: 'Unknown POS action.' });
    const session = res.locals.session as MemberSession;
    const payload = { ...req.body } as Record<string, unknown>;
    const verificationToken = String(payload.verificationToken || '').trim();
    delete payload.verificationToken;
    if (req.params.action === 'redeem-reward' && verificationToken) {
      verifyQrToken(verificationToken, 'reward-scan', String(payload.PhoneNumber || ''), String(payload.Reward_Id || ''));
    }
    if (req.params.action === 'redeem-reward') {
      const rewardId = String(payload.Reward_Id || '');
      await requireEligibleReward(String(payload.PhoneNumber || ''), rewardId, /^Voucher-/i.test(rewardId));
    }
    if (req.params.action === 'use-stamp') {
      const count = Number(payload.StampCount);
      if (!validPhone(payload.PhoneNumber) || !Number.isInteger(count) || count <= 0) return res.status(400).json({ message: 'Enter a valid member and a positive whole stamp count.' });
      const wallet = firstRecord(await xcode.post('MemberWallet/MemberGetWalletDetails', { PhoneNumber: payload.PhoneNumber }));
      if (count > Number(wallet.TotalStamp || 0)) return res.status(400).json({ message: 'The member does not have enough stamps.' });
    }
    if (action.merchantField) payload[action.merchantField] = session.merchantId;
    if (req.params.action === 'void-spend') {
      const records = recordList(await xcode.post('MerchantTransactionHistories/GetAllSpendRecordsFilterMerchant', { MerchantId: session.merchantId }));
      const spend = records.find(record => record.SpendId === payload.SpendId);
      if (!spend) return res.status(400).json({ message: 'This payment does not belong to the signed-in merchant.' });
      if (String(spend.Status).toLowerCase() === 'void') return res.status(409).json({ message: 'This payment is already void. Check the member balance before taking further action.' });
      const before = firstRecord(await xcode.post('MemberWallet/MemberGetWalletDetails', { PhoneNumber: spend.PhoneNumber }));
      const result = await xcode.post(action.endpoint, payload);
      assertActionSucceeded(result);
      const after = firstRecord(await xcode.post('MemberWallet/MemberGetWalletDetails', { PhoneNumber: spend.PhoneNumber }));
      const refunded = spend.PaymentMethod !== 'Wallet' || Math.round((Number(after.Balance) - Number(before.Balance)) * 100) >= Math.round(Number(spend.GrandAmount) * 100);
      return res.json({ result, walletRefundConfirmed: refunded, warning: refunded
        ? 'Payment marked void. Review any separately awarded stamps before closing the reversal.'
        : 'Payment marked void, but the wallet refund was not confirmed. Review the wallet and separately awarded stamps before closing the reversal.' });
    }
    if (req.params.action === 'void-topup') {
      const records = recordList(await xcode.post('MerchantTransactionHistories/GetAllTopUpRecordsFilterMerchant', { MerchantId: session.merchantId }));
      const record = records.find(item => (item.TopUpId ?? item.TopupId) === payload.TopupId);
      if (!record) return res.status(400).json({ message: 'This top-up does not belong to the signed-in merchant.' });
      if (String(record.Status).toLowerCase() === 'void') return res.status(409).json({ message: 'This top-up is already void.' });
    }
    if (req.params.action === 'topup') {
      const paymentReceived = payload.paymentReceived === true;
      delete payload.paymentReceived;
      const phone = String(payload.PhoneNumber || '').trim();
      const reference = String(payload.ReferenceNumber || '').trim();
      const amount = Number(payload.TopupAmount);
      if (!paymentReceived) return res.status(400).json({ message: 'Confirm that payment has been received before adding wallet credit.' });
      if (!validPhone(phone) || !reference || !Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({ message: 'Enter a valid member, positive top-up amount, and reference.' });
      }
      const staff = recordList(await xcode.post('ManageStaff/GetAllStaff', { MerchantId: session.merchantId }));
      if (!staff.some(item => item.StaffName === payload.StaffName)) {
        return res.status(400).json({ message: `Select staff registered under ${session.merchantId}. Add a staff member from the Staff page first.` });
      }
      // Creation can return text rather than a record. Resolve the exact ID from
      // merchant history, and never report a pending top-up as credited.
      const records = () => xcode.post('MerchantTransactionHistories/GetAllTopUpRecordsFilterMerchant', { MerchantId: session.merchantId });
      let record = recordList(await records()).find(item => item.ReferenceNumber === reference && item.PhoneNumber === phone);
      if (record && Number(record.TopupAmount) !== amount) return res.status(409).json({ message: 'This reference already belongs to a different top-up amount.' });
      if (!record) {
        const creation = await xcode.post(action.endpoint, payload);
        if (typeof creation === 'string' && /not found|invalid|incorrect|failed|error/i.test(creation)) {
          throw Object.assign(new Error(creation), { status: 400 });
        }
        record = recordList(await records()).find(item => item.ReferenceNumber === reference && item.PhoneNumber === phone);
      }
      const topupId = String(record?.TopUpId || '');
      if (!topupId) throw Object.assign(new Error('The top-up was not confirmed. Check Transactions before trying again.'), { status: 502 });
      if (record?.Status !== 'Paid') {
        await xcode.post('MerchantTopup/UpdateTopUpWallet', { Status: 'Paid', TopUpId: topupId, TopupReceipt: reference, IsPaid: 'Paid' });
      }
      const details = recordList(await records()).find(item => item.TopUpId === topupId);
      if (details?.Status !== 'Paid' || details?.IsPaid !== 'Paid') {
        throw Object.assign(new Error('The top-up is still awaiting payment confirmation. Check Transactions before trying again.'), { status: 502 });
      }
      const wallet = await xcode.post('MemberWallet/MemberGetWalletDetails', { PhoneNumber: phone });
      return res.json({ ...details, wallet });
    }
    const result = await xcode.post(action.endpoint, payload);
    assertActionSucceeded(result);
    res.json(result);
  } catch (error) { next(error); }
});

app.post('/pos/checkout', requireMerchant, async (req, res, next) => {
  let checkoutKey: string | undefined;
  try {
    const session = res.locals.session as MemberSession;
    const phoneNumber = String(req.body.phoneNumber || '').trim();
    const paymentMethod = String(req.body.paymentMethod || 'Cash');
    const staffName = String(req.body.staffName || '').trim();
    const staffPassword = String(req.body.staffPassword || '');
    const referenceNumber = String(req.body.referenceNumber || `SALE-${Date.now()}`).trim();
    const requestedDiscount = Number(req.body.discountAmount || 0);
    const stampUseCount = Number(req.body.stampUseCount ?? 0);
    const requestedLines = Array.isArray(req.body.items) ? req.body.items as CheckoutLine[] : [];

    if (!validPhone(phoneNumber)) return res.status(400).json({ message: 'Select a valid member before checkout.' });
    if (!['Cash', 'Wallet'].includes(paymentMethod)) return res.status(400).json({ message: 'Choose cash or Eduvo Wallet payment.' });
    if (!staffName || !staffPassword) return res.status(400).json({ message: 'A registered staff name and PIN are required.' });
    if (!requestedLines.length) return res.status(400).json({ message: 'Add at least one product to the order.' });
    if (!Number.isFinite(requestedDiscount) || requestedDiscount < 0 || !Number.isInteger(stampUseCount) || stampUseCount < 0) {
      return res.status(400).json({ message: 'Enter a valid discount and a whole, non-negative stamp count.' });
    }
    const key = `${session.merchantId}:${referenceNumber}`;
    if (checkoutInFlight.has(key)) return res.status(409).json({ message: 'This payment is already being processed. Check Transactions before retrying.' });
    checkoutInFlight.add(key);
    checkoutKey = key;
    const previous = recordList(await xcode.post('MerchantTransactionHistories/GetAllSpendRecordsFilterMerchant', { MerchantId: session.merchantId }));
    if (previous.some(record => record.ReferenceNumber === referenceNumber)) {
      return res.status(409).json({ message: 'This payment reference is already recorded. Check Transactions; do not charge the member again.' });
    }
    const staff = recordList(await xcode.post('ManageStaff/GetAllStaff', { MerchantId: session.merchantId }));
    if (!staff.some(record => record.StaffName === staffName && String(record.Password) === staffPassword)) {
      return res.status(400).json({ message: 'The staff name or password is incorrect for this merchant.' });
    }
    const walletBefore = firstRecord(await xcode.post('MemberWallet/MemberGetWalletDetails', { PhoneNumber: phoneNumber }));
    if (!walletBefore.WalletId) return res.status(400).json({ message: 'No wallet was found for this member.' });
    if (stampUseCount > Number(walletBefore.TotalStamp || 0)) return res.status(400).json({ message: 'The member does not have enough stamps.' });

    const catalog = await readCatalog();
    const byId = new Map(catalog.map(product => [product.id, product]));
    const items = requestedLines.map(line => {
      const product = byId.get(String(line.productId || ''));
      const quantity = Number(line.quantity || 0);
      if (!product || !Number.isInteger(quantity) || quantity < 1 || quantity > 50) {
        throw Object.assign(new Error('The order contains an unavailable product or invalid quantity.'), { status: 400 });
      }
      return { productId: product.id, name: product.name, price: Number(product.price), quantity, lineTotal: Number((product.price * quantity).toFixed(2)) };
    });
    const subtotal = Number(items.reduce((sum, item) => sum + item.lineTotal, 0).toFixed(2));
    const discountAmount = Number(Math.min(subtotal, Math.max(0, requestedDiscount)).toFixed(2));
    const grandAmount = Number((subtotal - discountAmount).toFixed(2));
    if (grandAmount <= 0) return res.status(400).json({ message: 'The final order total must be greater than zero.' });
    if (paymentMethod === 'Wallet' && grandAmount > Number(walletBefore.Balance || 0)) {
      return res.status(400).json({ message: 'The member does not have enough wallet balance.' });
    }

    const receiptText = items.map(item => `${item.quantity} x ${item.name} @ RM ${item.price.toFixed(2)}`).join('\n');
    const paymentPayload = {
      ReferenceNumber: referenceNumber,
      Amount: subtotal,
      PhoneNumber: phoneNumber,
      PaymentMethod: paymentMethod,
      ReceiptXaml: receiptText,
      UseStampDiscount: stampUseCount > 0,
      DiscountAmount: discountAmount,
      GrandAmount: grandAmount,
      StampUseCount: stampUseCount,
      StaffName: staffName,
      StaffPassword: staffPassword,
      MerchantId: session.merchantId,
    };
    const paymentEndpoint = paymentMethod === 'Wallet' ? 'MerchantSpend/WalletSpend' : 'MerchantSpend/CashSpend';
    const payment = await xcode.post(paymentEndpoint, paymentPayload);
    assertActionSucceeded(payment);
    const spendRecord = await confirmSpendRecord(phoneNumber, referenceNumber);
    if (!spendRecord) {
      throw Object.assign(new Error('The loyalty service did not confirm this payment in transaction history. No points or stamps were awarded.'), { status: 502 });
    }

    const pointMultiplier = Math.max(1, Number(walletBefore.PointBonus || 1));
    // Spend endpoints already award their configured purchase points. Do not
    // call AssignPoint again or members receive duplicate purchase points.
    const expectedPoints = Number(spendRecord.RewardPoint ?? Math.floor(grandAmount * pointMultiplier));
    const expectedStamps = 1;
    const loyaltyResults = await Promise.allSettled([
      Promise.resolve(expectedPoints),
      xcode.post('MerchantStamp/AssignStamp', {
        PhoneNumber: phoneNumber,
        StampCount: expectedStamps,
        Amount: grandAmount,
        StaffName: staffName,
        Merchant_Id: session.merchantId,
      }).then(result => { assertActionSucceeded(result); return result; }),
    ]);
    const pointsAwarded = loyaltyResults[0].status === 'fulfilled' ? expectedPoints : 0;
    const stampsAwarded = loyaltyResults[1].status === 'fulfilled' ? expectedStamps : 0;
    const loyaltyWarning = loyaltyResults.every(result => result.status === 'fulfilled')
      ? ''
      : 'Payment succeeded, but one or more loyalty updates need review in Loyalty actions.';
    const member = await xcode.post('MerchantScanMemberInfo/ScanGetMemberDetails', { Phone: phoneNumber }).catch(() => ({}));

    res.json({
      referenceNumber,
      items,
      subtotal,
      discountAmount,
      grandAmount,
      paymentMethod,
      payment,
      spendRecord,
      pointsAwarded,
      stampsAwarded,
      loyaltyWarning,
      member: withoutPassword(member),
    });
  } catch (error) { next(error); }
  finally { if (checkoutKey) checkoutInFlight.delete(checkoutKey); }
});

app.post('/pos/topups/details', requireMerchant, async (req, res, next) => {
  try {
    const topupId = String(req.body.topupId || '').trim();
    if (!topupId) return res.status(400).json({ message: 'A top-up record ID is required.' });
    res.json(await xcode.post('MerchantTransactionHistories/GetTopUpRecordDetails', { TopupId: topupId }));
  } catch (error) { next(error); }
});

app.get('/pos/staff', requireMerchant, async (_req, res, next) => {
  try {
    const session = res.locals.session as MemberSession;
    const staff = await xcode.post('ManageStaff/GetAllStaff', { MerchantId: session.merchantId });
    res.json(withoutPassword(staff));
  } catch (error) { next(error); }
});

app.post('/pos/staff', requireMerchant, async (req, res, next) => {
  try {
    const session = res.locals.session as MemberSession;
    const staffName = String(req.body.staffName || '').trim();
    const staffType = String(req.body.staffType || '').trim();
    const password = String(req.body.password || '');
    const phoneNumber = String(req.body.phoneNumber || '').trim();
    if (!staffName || !staffType || password.length < 4 || !validPhone(phoneNumber)) {
      return res.status(400).json({ message: 'Enter a staff name, role, valid phone number, and PIN of at least four characters.' });
    }
    const result = await xcode.post('ManageStaff/CreateStaff', { StaffName: staffName, StaffType: staffType, Password: password, PhoneNumber: phoneNumber, MerchantId: session.merchantId });
    res.status(201).json(withoutPassword(result));
  } catch (error) { next(error); }
});

app.post('/pos/staff/:staffId/delete', requireMerchant, async (req, res, next) => {
  try {
    const staffId = String(req.params.staffId || '').trim();
    if (!staffId) return res.status(400).json({ message: 'A staff ID is required.' });
    res.json(await xcode.post('ManageStaff/DeleteStaff', { StaffId: staffId }));
  } catch (error) { next(error); }
});

const posHistoryEndpoints: Record<string, string> = {
  topups: 'MerchantTransactionHistories/GetAllTopUpRecordsFilterMerchant',
  spends: 'MerchantTransactionHistories/GetAllSpendRecordsFilterMerchant',
  rewards: 'MerchantTransactionHistories/GetAllRewardRecordsFilterMerchant',
  vouchers: 'MerchantTransactionHistories/GetAllVoucherRecordsFilterMerchant',
  stamps: 'MerchantTransactionHistories/GetAllStampRecordsFilterMerchant',
  points: 'ManagePoint/GetAllPointAssignRecordByMerchantId'
};

app.get('/pos/history/:type', requireMerchant, async (req, res, next) => {
  try {
    const endpoint = posHistoryEndpoints[String(req.params.type)];
    if (!endpoint) return res.status(404).json({ message: 'Unknown transaction history.' });
    const session = res.locals.session as MemberSession;
    res.json(await xcode.post(endpoint, { MerchantId: session.merchantId }));
  } catch (error) { next(error); }
});

const posMemberHistoryEndpoints: Record<string, { endpoint: string; phoneField: string }> = {
  spends: { endpoint: 'MerchantTransactionHistories/GetMemberSpendRecords', phoneField: 'PhoneNumber' },
  topups: { endpoint: 'MerchantTransactionHistories/GetTopUpRecordsFilterByMember', phoneField: 'Phone' },
  rewards: { endpoint: 'MerchantTransactionHistories/GetAllRewardsRecordsFilterByMember', phoneField: 'Phone' },
  vouchers: { endpoint: 'MerchantTransactionHistories/GetAllVoucherRecordsFilterByMember', phoneField: 'Phone' }
};

app.post('/pos/member/history/:type', requireMerchant, async (req, res, next) => {
  try {
    const route = posMemberHistoryEndpoints[String(req.params.type)];
    if (!route) return res.status(404).json({ message: 'That member history category is unavailable.' });
    const phone = String(req.body.phone || '').trim();
    if (!validPhone(phone)) return res.status(400).json({ message: 'Enter a valid member phone number.' });
    res.json(await xcode.post(route.endpoint, { [route.phoneField]: phone }));
  } catch (error) { next(error); }
});

app.post('/pos/notifications/:audience', requireMerchant, async (req, res, next) => {
  try {
    const audience = String(req.params.audience);
    if (!['all', 'member'].includes(audience)) return res.status(404).json({ message: 'Unknown notification audience.' });
    const header = String(req.body.NotificationHeader || '').trim();
    const body = String(req.body.NotificationBody || '').trim();
    if (!header || !body) return res.status(400).json({ message: 'Enter a notification title and message.' });
    const payload: Record<string, unknown> = {
      Type: String(req.body.Type || 'Merchant'),
      TargetId: String(req.body.TargetId || ''),
      NotificationHeader: header,
      NotificationBody: body
    };
    if (audience === 'member') {
      const phone = String(req.body.PhoneNumber || '').trim();
      if (!validPhone(phone)) return res.status(400).json({ message: 'Select a member or enter a valid phone number.' });
      payload.PhoneNumber = phone;
      payload.DeviceId = String(req.body.DeviceId || '');
    }
    const result = await notificationStore.send(audience === 'member' ? String(payload.PhoneNumber) : null, header, body, `merchant:${(res.locals.session as MemberSession).merchantId}`);
    assertActionSucceeded(result);
    res.json(result);
  } catch (error) { next(error); }
});

app.post('/pos/eod', requireMerchant, async (req, res, next) => {
  try {
    const session = res.locals.session as MemberSession;
    const selectDate = req.body.selectDate || new Date().toISOString();
    res.json(await xcode.post('MerchantTransactionHistories/MerchantPrintEOD', { MerchantId: session.merchantId, SelectDate: selectDate }));
  } catch (error) { next(error); }
});

app.post('/auth/request-otp', async (req, res, next) => {
  try {
    const { phoneNumber, deviceId = '00000000-0000-4000-8000-000000000001' } = req.body;
    if (!validPhone(phoneNumber)) return res.status(400).json({ message: 'Enter a valid phone number.' });
    const targetDeviceId = String(deviceId || '').trim() || '00000000-0000-4000-8000-000000000001';
    const existingMember = await findOptionalMember('MemberDetails/GetMemberDetails', { PhoneNumber: phoneNumber });
    const registeredDeviceId = String(firstRecord(existingMember).DeviceId || '').trim();
    const otpDeviceId = registeredDeviceId || targetDeviceId;
    const data = await xcode.post('MemberAccount/RequestOTP', { PhoneNumber: phoneNumber, DeviceId: otpDeviceId });
    if (!extractOtp(data)) return res.status(502).json({ message: 'The loyalty service could not issue a login code for this account.' });
    loginOtpDevices.set(phoneNumber, { otpDeviceId, targetDeviceId, otp: extractOtp(data)!, attempts: 0, expiresAt: Date.now() + 5 * 60 * 1000 });
    res.json(data);
  } catch (error) { next(error); }
});

app.post('/auth/register-otp', async (req, res, next) => {
  try {
    const { phoneNumber, deviceId = '00000000-0000-4000-8000-000000000001' } = req.body;
    if (!validPhone(phoneNumber)) return res.status(400).json({ message: 'Enter a valid phone number.' });
    res.json(await xcode.post('MemberAccount/RegisterOtp', { PhoneNumber: phoneNumber, DeviceId: deviceId }));
  } catch (error) { next(error); }
});

app.post('/auth/login/phone', async (req, res, next) => {
  try {
    const { phoneNumber, otp, firstLogin = 'True', accountStatus = '', deviceId = '00000000-0000-4000-8000-000000000001' } = req.body;
    if (!validPhone(phoneNumber) || typeof otp !== 'string' || !/^\d{6}$/.test(otp)) return res.status(400).json({ message: 'Enter a valid phone number and six-digit verification code.' });
    const isFirstLogin = firstLogin === true || String(firstLogin).toLowerCase() === 'true';
    const pendingDevice = loginOtpDevices.get(phoneNumber);
    const activePendingDevice = pendingDevice && pendingDevice.expiresAt > Date.now() ? pendingDevice : undefined;
    if (!activePendingDevice || activePendingDevice.attempts >= 5 || activePendingDevice.otp !== otp) {
      if (activePendingDevice) activePendingDevice.attempts++;
      return res.status(400).json({ message: 'The verification code is invalid or expired. Request a new code.' });
    }
    const loginDeviceId = activePendingDevice?.otpDeviceId || String(deviceId);
    const member = await xcode.post('MemberLogin/MemberMobileLoginGetProfile', { Phone: phoneNumber, OTP: otp, FirstLogin: isFirstLogin, DeviceId: loginDeviceId, AccountStatus: accountStatus });
    loginOtpDevices.delete(phoneNumber);
    const targetDeviceId = activePendingDevice?.targetDeviceId || String(deviceId);
    if (targetDeviceId && targetDeviceId !== loginDeviceId) {
      await xcode.post('MemberLogin/UpdateDeviceId', { PhoneNumber: phoneNumber, DeviceId: targetDeviceId }).catch(() => undefined);
    }
    res.json({ member: withoutPassword(member), sessionToken: issueMemberSession({ phoneNumber }) });
  } catch (error) { next(error); }
});

app.post('/auth/login/email', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!validEmail(email) || typeof password !== 'string' || !password) return res.status(400).json({ message: 'Enter a valid email and password.' });
    const member = await xcode.post('MemberLogin/CheckEmailPassword', { Email: email, Password: password });
    const phoneNumber = String(firstRecord(member).PhoneNumber || '');
    res.json({ member: withoutPassword(member), sessionToken: issueMemberSession({ email, ...(phoneNumber ? { phoneNumber } : {}) }) });
  } catch (error) { next(error); }
});

app.post('/auth/keep-login', async (req, res, next) => {
  try {
    const { phoneNumber, deviceId } = req.body;
    if (!validPhone(phoneNumber) || typeof deviceId !== 'string' || !deviceId) return res.status(400).json({ message: 'A valid phone number and device ID are required.' });
    const result = await xcode.post('MemberAccount/KeepLoginUser', { PhoneNumber: phoneNumber, DeviceId: deviceId });
    const member = await xcode.post('MemberDetails/GetMemberDetails', { PhoneNumber: phoneNumber });
    res.json({ keepLogin: result, member: withoutPassword(member), sessionToken: issueMemberSession({ phoneNumber }) });
  } catch (error) { next(error); }
});

app.post('/members/:phoneNumber/device', requireSession, async (req, res, next) => {
  try {
    const phoneNumber = memberPhone(req, res);
    if (!phoneNumber) return;
    const deviceId = String(req.body.deviceId || '').trim();
    if (!deviceId) return res.status(400).json({ message: 'A push notification device token is required.' });
    res.json(await xcode.post('MemberLogin/UpdateDeviceId', { PhoneNumber: phoneNumber, DeviceId: deviceId }));
  } catch (error) { next(error); }
});

app.post('/auth/password-reset/request', async (req, res, next) => {
  try {
    const { phoneNumber, deviceId = '00000000-0000-4000-8000-000000000001' } = req.body;
    if (!validPhone(phoneNumber)) return res.status(400).json({ message: 'Enter a valid phone number.' });
    const result = await xcode.post('MemberAccount/RequestOTP', { PhoneNumber: phoneNumber, DeviceId: deviceId });
    const code = String(firstRecord(result).OTP || '');
    if (!/^\d{6}$/.test(code)) return res.status(502).json({ message: 'The loyalty service did not return a valid reset code.' });
    resetOtps.set(phoneNumber, { code, expiresAt: Date.now() + 5 * 60 * 1000 });
    res.json(result);
  } catch (error) { next(error); }
});

app.post('/auth/password-reset/confirm', async (req, res, next) => {
  try {
    const { phoneNumber, otp, newPassword } = req.body;
    if (!validPhone(phoneNumber) || typeof otp !== 'string' || !/^\d{6}$/.test(otp) || typeof newPassword !== 'string' || newPassword.length < 8) {
      return res.status(400).json({ message: 'Enter a valid phone number, six-digit code, and password of at least 8 characters.' });
    }
    const pending = resetOtps.get(phoneNumber);
    if (!pending || pending.expiresAt < Date.now() || pending.code !== otp) return res.status(400).json({ message: 'The reset code is invalid or expired.' });
    const result = await xcode.post('MemberAccount/MemberResetPassword', { PhoneNumber: phoneNumber, NewPassword: newPassword });
    resetOtps.delete(phoneNumber);
    res.json(result);
  } catch (error) { next(error); }
});

app.post('/auth/register', async (req, res, next) => {
  try {
    const { name, email, phoneNumber, referralBy = '', password, birthday = '' } = req.body;
    if (typeof name !== 'string' || name.trim().length < 2 || !validEmail(email) || !validPhone(phoneNumber) || typeof password !== 'string' || password.length < 8) {
      return res.status(400).json({ message: 'Enter a name, valid email, valid phone number, and password of at least 8 characters.' });
    }
    const member = await xcode.post('MemberLogin/RegisterMember', { Name: name, Email: email, PhoneNumber: phoneNumber, ReferralBy: referralBy, Password: password, Birthday: birthday, EmailSubcribe: 'true', Image: '', ImageByte: '' });
    res.status(201).json({ member: withoutPassword(member), sessionToken: issueMemberSession({ phoneNumber, email }) });
  } catch (error) { next(error); }
});

app.post('/member/referral/check', async (req, res, next) => {
  try {
    const { referralCode } = req.body;
    if (!referralCode) return res.status(400).json({ message: 'referralCode is required.' });
    res.json(await xcode.post('MemberWallet/CheckReffererCodeValid', { ReferralCode: referralCode }));
  } catch (error) { next(error); }
});

app.post('/member/availability', async (req, res, next) => {
  try {
    const { phoneNumber, email } = req.body;
    if (!phoneNumber || !email) return res.status(400).json({ message: 'phoneNumber and email are required.' });
    const [phoneMember, emailMember] = await Promise.all([
      findOptionalMember('ManageMember/FindMemberByPhone', { PhoneNumber: phoneNumber }),
      findOptionalMember('ManageMember/FindMemberByEmail', { Email: email })
    ]);
    res.json({ phoneAvailable: !hasMemberRecord(phoneMember), emailAvailable: !hasMemberRecord(emailMember) });
  } catch (error) { next(error); }
});

app.get('/members/:phoneNumber/qr', requireSession, (req, res) => {
  const { phoneNumber } = req.params;
  const session = res.locals.session as MemberSession;
  if (!session.phoneNumber || session.phoneNumber !== phoneNumber) {
    return res.status(403).json({ message: 'You can only create a QR code for your own member account.' });
  }
  // The QR contains a random, short-lived backend reference rather than a dense profile/JWT payload.
  const qrToken = issueQrToken({ purpose: 'member-scan', phoneNumber });
  res.json({ qrToken, expiresInSeconds: 300 });
});

app.get('/members/:phoneNumber/rewards/:rewardId/qr', requireSession, async (req, res, next) => {
  try {
  const phoneNumber = memberPhone(req, res);
  if (!phoneNumber) return;
  const rewardId = String(req.params.rewardId || '');
  const kind = req.query.kind === 'voucher' ? 'voucher' : 'reward';
  await requireEligibleReward(phoneNumber, rewardId, kind === 'voucher');
  const qrToken = issueQrToken({ purpose: 'reward-scan', phoneNumber, rewardId, kind });
  res.json({ qrToken, rewardId, kind, expiresInSeconds: 300 });
  } catch (error) { next(error); }
});

app.get('/members/:phoneNumber/rewards/:rewardId', requireSession, async (req, res, next) => {
  try {
    const phoneNumber = memberPhone(req, res);
    if (!phoneNumber) return;
    const voucher = req.query.kind === 'voucher';
    const data = voucher
      ? await xcode.post('MemberVoucher/GetVoucherById', { RewardId: req.params.rewardId, PhoneNumber: phoneNumber })
      : await xcode.post('MemberReward/FindReward', { RewardId: req.params.rewardId });
    res.json(data);
  } catch (error) { next(error); }
});

app.get('/members/:phoneNumber/history/:type', requireSession, async (req, res, next) => {
  try {
    const phoneNumber = memberPhone(req, res);
    if (!phoneNumber) return;
    const endpoints: Record<string, string> = {
      all: 'History/GetAllRecordByPhoneNumber', topups: 'History/GetTopUpRecordByPhoneNumber',
      payments: 'History/GetPaymentRecordByPhoneNumber', points: 'History/GetAssignPointRecordByPhoneNumber',
      stamps: 'History/GetAssignStampRecordByPhoneNumber', stampuse: 'History/GetStampRecordByPhoneNumber',
      rewards: 'MerchantTransactionHistories/GetAllRewardsRecordsFilterByMember', vouchers: 'MerchantTransactionHistories/GetAllVoucherRecordsFilterByMember',
      spends: 'MemberAccount/GetSpendRecords', voucherhistory: 'MemberAccount/GetMemberVoucherHistories'
    };
    const endpoint = endpoints[String(req.params.type).toLowerCase()];
    if (!endpoint) return res.status(400).json({ message: 'Unsupported history filter.' });
    const kind = String(req.params.type).toLowerCase();
    const records = await xcode.post(endpoint, kind === 'rewards' || kind === 'vouchers' ? { Phone: phoneNumber } : { PhoneNumber: phoneNumber });
    if (kind === 'all') {
      const [rewards, vouchers] = await Promise.all([
        xcode.post('MerchantTransactionHistories/GetAllRewardsRecordsFilterByMember', { Phone: phoneNumber }),
        xcode.post('MerchantTransactionHistories/GetAllVoucherRecordsFilterByMember', { Phone: phoneNumber })
      ]);
      return res.json(mergeRedemptionHistory(recordList(records), [...recordList(rewards), ...recordList(vouchers)]));
    }
    res.json(records);
  } catch (error) { next(error); }
});

app.get('/members/:phoneNumber/topups/:topupId', requireSession, async (req, res, next) => {
  try {
    if (!memberPhone(req, res)) return;
    res.json(await xcode.post('MemberAccount/GetTopUpRecordDetails', { TopupId: req.params.topupId }));
  } catch (error) { next(error); }
});

app.post('/members/:phoneNumber/addresses', requireSession, async (req, res, next) => {
  try {
    const phoneNumber = memberPhone(req, res);
    if (!phoneNumber) return;
    const { address, latitude = 0, longitude = 0, receiverPhone, receiverName } = req.body;
    if (typeof address !== 'string' || !address.trim() || !validPhone(receiverPhone) || typeof receiverName !== 'string' || !receiverName.trim()) {
      return res.status(400).json({ message: 'Enter a delivery address, receiver name, and valid receiver phone number.' });
    }
    res.status(201).json(await xcode.post('ManagemMemberAddress/AddMemberAddress', {
      MemberPhone: phoneNumber, Address: address.trim(), Latitude: Number(latitude) || 0, Longitude: Number(longitude) || 0,
      ReceiverPhone: receiverPhone.trim(), ReceiverName: receiverName.trim()
    }));
  } catch (error) { next(error); }
});

app.post('/members/:phoneNumber/addresses/:addressId', requireSession, async (req, res, next) => {
  try {
    const phoneNumber = memberPhone(req, res);
    if (!phoneNumber) return;
    const { address, latitude = 0, longitude = 0, receiverPhone, receiverName, isDefault = false } = req.body;
    if (typeof address !== 'string' || !address.trim() || !validPhone(receiverPhone) || typeof receiverName !== 'string' || !receiverName.trim()) {
      return res.status(400).json({ message: 'Enter a delivery address, receiver name, and valid receiver phone number.' });
    }
    res.json(await xcode.post('ManagemMemberAddress/EditMemberAddress', {
      AddressId: req.params.addressId, MemberPhone: phoneNumber, Address: address.trim(), Latitude: Number(latitude) || 0,
      Longitude: Number(longitude) || 0, ReceiverPhone: receiverPhone.trim(), ReceiverName: receiverName.trim(), IsDefault: Boolean(isDefault)
    }));
  } catch (error) { next(error); }
});

app.delete('/members/:phoneNumber/addresses/:addressId', requireSession, async (req, res, next) => {
  try {
    if (!memberPhone(req, res)) return;
    res.json(await xcode.post('ManagemMemberAddress/DeleteMemberAddress', { AddressId: req.params.addressId }));
  } catch (error) { next(error); }
});

app.get('/members/:phoneNumber/notifications', requireSession, async (req, res, next) => {
  try {
    const phoneNumber = memberPhone(req, res);
    if (!phoneNumber) return;
    res.json(await memberNotificationOperation('MemberNotification/GetNotificationsFilterMember', { PhoneNumber: phoneNumber }));
  } catch (error) { next(error); }
});

app.get('/members/:phoneNumber/notifications/:notificationId', requireSession, async (req, res, next) => {
  try {
    const phoneNumber = memberPhone(req, res);
    if (!phoneNumber) return;
    res.json(await memberNotificationOperation('MemberNotification/GetNotificationsDetails', { PhoneNumber: phoneNumber, Notification_Id: req.params.notificationId }));
  } catch (error) { next(error); }
});

app.post('/members/:phoneNumber/notifications/:notificationId/read', requireSession, async (req, res, next) => {
  try {
    const phoneNumber = memberPhone(req, res);
    if (!phoneNumber) return;
    const result = await memberNotificationOperation('MemberNotification/UserReadNotification', { PhoneNumber: phoneNumber, NotificationId: req.params.notificationId });
    assertActionSucceeded(result);
    res.json(result);
  } catch (error) { next(error); }
});

app.post('/members/:phoneNumber/notifications/read-all', requireSession, async (req, res, next) => {
  try {
    const phoneNumber = memberPhone(req, res);
    if (!phoneNumber) return;
    const result = await memberNotificationOperation('MemberNotification/UserReadAllNotification', { PhoneNumber: phoneNumber });
    assertActionSucceeded(result);
    res.json(result);
  } catch (error) { next(error); }
});

app.post('/members/:phoneNumber/email-verification/request', requireSession, async (req, res, next) => {
  try {
    const phoneNumber = memberPhone(req, res);
    if (!phoneNumber) return;
    const result = await xcode.post('MemberAccount/GenerateMailOTP', { PhoneNumber: phoneNumber, DeviceId: '' });
    const code = extractOtp(result);
    if (!/^\d{4,10}$/.test(code)) return res.status(502).json({ message: 'The loyalty service did not return a valid email verification code.' });
    emailOtps.set(phoneNumber, { code, expiresAt: Date.now() + 10 * 60 * 1000 });
    res.json({ requested: true, ...(config.nodeEnv === 'development' ? { OTP: code } : {}) });
  } catch (error) { next(error); }
});

app.post('/members/:phoneNumber/email-verification/confirm', requireSession, async (req, res, next) => {
  try {
    const phoneNumber = memberPhone(req, res);
    if (!phoneNumber) return;
    const pending = emailOtps.get(phoneNumber);
    if (!pending || pending.expiresAt < Date.now() || pending.code !== String(req.body.otp || '')) return res.status(400).json({ message: 'The verification code is invalid or expired.' });
    const result = await xcode.post('MemberAccount/UpdateAccountVerify', { PhoneNumber: phoneNumber, Type: 'Email' });
    emailOtps.delete(phoneNumber);
    res.json(result);
  } catch (error) { next(error); }
});

app.post('/members/:phoneNumber/deactivate', requireSession, async (req, res, next) => {
  try {
    const phoneNumber = memberPhone(req, res);
    if (!phoneNumber) return;
    res.json(await xcode.post('MemberAccount/UpdateAccountStatusDeactive', { PhoneNumber: phoneNumber }));
  } catch (error) { next(error); }
});

app.get('/app/versions', async (_req, res, next) => {
  try { res.json(await xcode.get('ManageVersion/GetAllVersion')); } catch (error) { next(error); }
});

app.post('/members/:phoneNumber/profile', requireSession, async (req, res, next) => {
  try {
    const { phoneNumber } = req.params;
    const session = res.locals.session as MemberSession;
    const { name, email, birthday = '', imageByte = '' } = req.body;
    if (session.phoneNumber !== phoneNumber) return res.status(403).json({ message: 'You can only update your own profile.' });
    if (typeof name !== 'string' || name.trim().length < 2 || !validEmail(email)) return res.status(400).json({ message: 'Enter a valid name and email address.' });
    const member = await xcode.post('MemberAccount/MemberEditProfile', { PhoneNumber: phoneNumber, UserName: name.trim(), Email: email.trim(), Birthday: birthday, ImageByte: imageByte });
    res.json({ member: withoutPassword(member) });
  } catch (error) { next(error); }
});

app.post('/members/:phoneNumber/feedback', requireSession, async (req, res, next) => {
  try {
    const { phoneNumber } = req.params;
    const session = res.locals.session as MemberSession;
    const { description } = req.body;
    if (session.phoneNumber !== phoneNumber) return res.status(403).json({ message: 'You can only submit feedback for your own account.' });
    if (typeof description !== 'string' || !description.trim()) return res.status(400).json({ message: 'Enter feedback before sending.' });
    const member = await xcode.post('MemberDetails/GetMemberDetails', { PhoneNumber: phoneNumber });
    const record = Array.isArray(member) ? member[0] : member as Record<string, unknown>;
    const feedback = await xcode.post('FeedBack/CreateFeedback', { Title: 'Member app feedback', Description: description.trim(), Rating: '', Category: 'Member App', UserId: record?.UserId || '', Location: '' });
    res.status(201).json(feedback);
  } catch (error) { next(error); }
});

app.get('/members/:phoneNumber/dashboard', requireSession, async (req, res, next) => {
  try {
    const { phoneNumber } = req.params;
    const session = res.locals.session as MemberSession;
    if (session.phoneNumber && session.phoneNumber !== phoneNumber) return res.status(403).json({ message: 'You can only access your own member dashboard.' });
    const [member, wallet] = await Promise.all([
      xcode.post('MemberDetails/GetMemberDetails', { PhoneNumber: phoneNumber }),
      xcode.post('MemberWallet/MemberGetWalletDetails', { PhoneNumber: phoneNumber }),
    ]);
    const record = firstRecord(member);
    const referralCode = String(record.ReferralCode || '');
    const userId = String(record.UserId || '');
    const [rewards, voucherCatalogue, stampProgramme, vouchers, history, outlets, notifications, redeemedRewards, addresses, highlights, activeStamps, usedStamps, referrals, feedbackHistory] = await Promise.all([
      xcode.get('MemberReward/GetRewards').catch(() => []),
      xcode.get('MemberVoucher/GetAllVoucher').catch(() => []),
      xcode.get('ManageStamp/GetAllStamps').catch(() => []),
      xcode.post('MemberVoucher/GetVoucherByPhone', { PhoneNumber: phoneNumber }).catch(() => []),
      xcode.post('History/GetAllRecordByPhoneNumber', { PhoneNumber: phoneNumber }).catch(() => []),
      xcode.get('ManageOutlets/GetAllOutlets').catch(() => []),
      memberNotificationOperation('MemberNotification/GetNotificationsFilterMember', { PhoneNumber: phoneNumber }).catch(() => []),
      xcode.post('MemberAccount/GetMemberReward', { PhoneNumber: phoneNumber }).catch(() => []),
      xcode.post('ManagemMemberAddress/GetAllMemberAddress', { PhoneNumber: phoneNumber }).catch(() => []),
      xcode.get('ManageHighlight/UserGetAllHighlight').catch(() => []),
      xcode.post('MemberAccount/GetMemberStampList', { PhoneNumber: phoneNumber }).catch(() => []),
      xcode.post('MemberAccount/GetMemberStampUsedRecord', { PhoneNumber: phoneNumber }).catch(() => []),
      referralCode ? xcode.post('MemberAccount/GetMemberDownlineList', { ReferralCode: referralCode }).catch(() => []) : Promise.resolve([]),
      userId ? xcode.post('FeedBack/GetFeedbackListFilterUser', { UserId: userId }).catch(() => []) : Promise.resolve([])
    ]);
    res.json({ member: withoutPassword(member), wallet, rewards, voucherCatalogue, stampProgramme, vouchers, history, outlets, notifications, redeemedRewards, addresses, highlights, activeStamps, usedStamps, referrals, feedbackHistory });
  } catch (error) { next(error); }
});

app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const localError = error instanceof Error ? error as Error & { status?: number } : undefined;
  const upstream = typeof error === 'object' && error && 'response' in error
    ? (error as { response?: { status?: number; data?: unknown } }).response
    : undefined;
  const status = upstream?.status || localError?.status || 500;
  const body = upstream?.data;
  const upstreamMessage = typeof body === 'string'
    ? body
    : body && typeof body === 'object'
      ? String((body as Record<string, unknown>).message || (body as Record<string, unknown>).Message || (body as Record<string, unknown>).error || '')
      : '';
  // Do not log the Axios request config: it contains the bearer token.
  console.error(`Loyalty gateway error (${status}): ${upstreamMessage || 'No API error message returned.'}`);
  const configurationError = error instanceof Error && error.message.startsWith('XCODE_');
  res.status(status).json({ message: configurationError ? error.message : (upstreamMessage || localError?.message || 'The loyalty service request failed.') });
});

app.listen(config.port, () => console.log(`Loyalty backend listening on http://localhost:${config.port}`));
