'use strict';

const { LocalImportPoolError } = require('../pool/local-import-pool');
const { WorkstationAutomationError, generatePhoneClaimKey } = require('./automation-client');

class WorkstationInventoryImportCoordinator {
  constructor({ client, pool, minAgeMinutes = 45 } = {}) {
    if (!client) throw new TypeError('workstation automation client is required');
    if (!pool) throw new TypeError('local import pool is required');
    this.client = client;
    this.pool = pool;
    this.minAgeMinutes = minAgeMinutes;
  }

  async syncAccounts() {
    const inventory = await this.client.getAccountImportLines();
    return this.pool.syncInventoryAccounts(inventory);
  }

  async beginNextAccountAttempt() {
    const sync = await this.syncAccounts();
    const account = await this.pool.beginNextAccountAttempt({ inventoryOnly: true });
    return { sync, account };
  }

  async preparePhone(accountId) {
    let claim = await this.pool.getAccountPhoneClaim(accountId);
    if (claim?.status === 'invalid' && claim.phoneId && !claim.remoteUnavailableSynced) {
      await this.client.setPhoneUnavailable(claim.phoneId, true);
      await this.pool.markAccountPhoneClaimUnavailableSynced(accountId);
      claim = await this.pool.getAccountPhoneClaim(accountId);
    }
    if (!claim || claim.status === 'invalid') {
      const eligible = await this.client.getEligiblePhones({ minAgeMinutes: this.minAgeMinutes, limit: 1 });
      if (eligible.length === 0) {
        throw new LocalImportPoolError('No workstation phone is currently eligible', {
          code: 'no_available_phone',
        });
      }
      const mapping = await this.pool.findPhoneMapping(eligible[0].number);
      if (!mapping) {
        throw new LocalImportPoolError('Eligible workstation phone has no local SMS mapping', {
          code: 'phone_mapping_missing',
        });
      }
      claim = await this.pool.ensureAccountPhoneClaim(accountId, generatePhoneClaimKey());
    }

    if (claim.status === 'pending') {
      let result;
      try {
        result = await this.client.claimPhone({
          idempotencyKey: claim.idempotencyKey,
          minAgeMinutes: this.minAgeMinutes,
        });
      } catch (error) {
        if (error instanceof WorkstationAutomationError && !error.outcomeUnknown && !error.retryable) {
          await this.pool.abandonAccountPhoneClaim(accountId, error.code || `http_${error.status || 0}`);
        }
        throw error;
      }
      claim = await this.pool.recordAccountPhoneClaim(accountId, {
        idempotencyKey: claim.idempotencyKey,
        phoneId: result.phone.id,
        phoneNumber: result.phone.number,
        claimedAt: result.claimedAt,
        replayed: result.replayed,
      });
    }

    const mapping = await this.pool.findPhoneMapping(claim.phoneNumber);
    if (!mapping) {
      throw new LocalImportPoolError('Claimed workstation phone has no local SMS mapping', {
        code: 'phone_mapping_missing',
      });
    }
    return {
      phone: mapping.phone,
      smsAccessUrl: mapping.smsAccessUrl,
      allowSmsResend: mapping.allowResend,
      localPhoneId: mapping.id,
      remotePhoneId: claim.phoneId,
    };
  }

  async markPhoneSubmitted(localPhoneId) {
    await this.pool.markPhoneUsed(localPhoneId);
  }

  async markPhoneInvalid({ accountId, localPhoneId, remotePhoneId, reason }) {
    await this.pool.markAccountPhoneClaimInvalid(accountId, reason);
    await this.pool.markPhoneInvalid(localPhoneId, reason);
    await this.client.setPhoneUnavailable(remotePhoneId, true);
    await this.pool.markAccountPhoneClaimUnavailableSynced(accountId);
  }
}

module.exports = { WorkstationInventoryImportCoordinator };
