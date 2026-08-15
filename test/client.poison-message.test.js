const crypto = require('crypto');
const Client = require('../src/client');

describe('Client poison message handling', function() {
  it('drops an invalid ECDH public key without throwing', function() {
    const dh = crypto.createECDH('prime256v1');
    dh.generateKeys();

    const client = new Client(
      {
        keys : {
          privateKey : dh.getPrivateKey().toString('base64'),
          authSecret : crypto.randomBytes(16).toString('base64'),
        },
      },
      []
    );
    const dropped = [];
    client.on('ON_NOTIFICATION_DROPPED', event => dropped.push(event));

    expect(() =>
      client._onDataMessage({
        persistentId : 'poison-message-1',
        appData      : [
          { key : 'crypto-key', value : 'dh=AAAA' },
          {
            key   : 'encryption',
            value : `salt=${crypto.randomBytes(16).toString('base64')}`,
          },
        ],
        rawData : Buffer.from('invalid'),
      })
    ).not.toThrow();

    expect(dropped).toHaveLength(1);
    expect(dropped[0].persistentId).toEqual('poison-message-1');
    expect(dropped[0].error.code).toEqual('ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY');
    expect(client._persistentIds).toContain('poison-message-1');
  });

  it('does not acknowledge a missing persistent id', function() {
    const client = new Client({ keys : {} }, []);
    const dropped = [];
    client.on('ON_NOTIFICATION_DROPPED', event => dropped.push(event));

    expect(() =>
      client._onDataMessage({
        appData : [],
      })
    ).not.toThrow();

    expect(dropped).toHaveLength(1);
    expect(dropped[0].error.code).toEqual('FCM_DECRYPT_ERROR');
    expect(client._persistentIds).toHaveLength(0);
  });
});
