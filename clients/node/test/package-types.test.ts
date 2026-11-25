import {
  access,
  ConvenientSecurityError,
  DEFAULT_BRIDGE_PATH,
  DeniedError,
  ReferenceNotFoundError,
  type AccessOptions,
} from 'convenient-security';

const options: AccessOptions = {
  reason: 'type declaration test',
  ttl: 60,
};

// A grant with no clock: ttl may be omitted.
const ttlFreeOptions: AccessOptions = {
  reason: 'type declaration test without a ttl',
};

async function typecheckPublicApi(): Promise<void> {
  const values: Record<string, string> = await access(['op://demo/key'], options);
  const ttlFreeValues: Record<string, string> = await access(['op://demo/key'], ttlFreeOptions);
  void ttlFreeValues;
  const path: string = DEFAULT_BRIDGE_PATH;
  const error: ConvenientSecurityError = new DeniedError();
  const code: string | undefined = error.code;
  const missing: ConvenientSecurityError = new ReferenceNotFoundError('csec://demo/KEY: no such key');
  void missing;

  void values;
  void path;
  void code;
}

void typecheckPublicApi;

// @ts-expect-error ttl is expressed in seconds as a number.
void access(['op://demo/key'], { reason: 'invalid type fixture', ttl: '60' });
