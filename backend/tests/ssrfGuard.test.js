/**
 * SSRF Guard Unit Tests  v1.0
 */
'use strict';

jest.mock('dns', () => ({
  promises: {
    resolve4: jest.fn(),
  },
}));

const dns     = require('dns').promises;
const { validateOutboundUrl, isPrivateIp, isMetadataEndpoint } = require('../middleware/ssrfGuard');

describe('isPrivateIp', () => {
  test('detects loopback', () => { expect(isPrivateIp('127.0.0.1')).toBe(true); });
  test('detects RFC1918 10.x', () => { expect(isPrivateIp('10.0.0.1')).toBe(true); });
  test('detects RFC1918 172.16.x', () => { expect(isPrivateIp('172.16.0.1')).toBe(true); });
  test('detects RFC1918 192.168.x', () => { expect(isPrivateIp('192.168.1.100')).toBe(true); });
  test('detects link-local', () => { expect(isPrivateIp('169.254.169.254')).toBe(true); });
  test('passes public IP', () => { expect(isPrivateIp('8.8.8.8')).toBe(false); });
  test('passes public IP 2', () => { expect(isPrivateIp('1.1.1.1')).toBe(false); });
});

describe('isMetadataEndpoint', () => {
  test('blocks AWS IMDS', () => { expect(isMetadataEndpoint('169.254.169.254')).toBe(true); });
  test('blocks GCP metadata', () => { expect(isMetadataEndpoint('metadata.google.internal')).toBe(true); });
  test('allows public URL', () => { expect(isMetadataEndpoint('api.openai.com')).toBe(false); });
});

describe('validateOutboundUrl', () => {
  test('blocks non-http protocol', async () => {
    const r = await validateOutboundUrl('ftp://evil.com/data');
    expect(r.safe).toBe(false);
    expect(r.reason).toMatch(/blocked_protocol/);
  });

  test('blocks metadata endpoint URL', async () => {
    const r = await validateOutboundUrl('http://169.254.169.254/latest/meta-data/');
    expect(r.safe).toBe(false);
    expect(r.reason).toBe('metadata_endpoint_blocked');
  });

  test('blocks URL that resolves to private IP', async () => {
    dns.resolve4.mockResolvedValue(['10.0.0.1']);
    const r = await validateOutboundUrl('http://internal-host.example.com/data');
    expect(r.safe).toBe(false);
    expect(r.reason).toMatch(/dns_resolves_to_private/);
  });

  test('allows public URL resolving to public IP', async () => {
    dns.resolve4.mockResolvedValue(['8.8.8.8']);
    const r = await validateOutboundUrl('https://api.openai.com/v1/chat');
    expect(r.safe).toBe(true);
  });

  test('rejects invalid URL string', async () => {
    const r = await validateOutboundUrl('not-a-url');
    expect(r.safe).toBe(false);
    expect(r.reason).toBe('url_parse_failed');
  });

  test('rejects null input', async () => {
    const r = await validateOutboundUrl(null);
    expect(r.safe).toBe(false);
    expect(r.reason).toBe('invalid_url');
  });
});
