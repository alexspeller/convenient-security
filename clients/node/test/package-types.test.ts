import {
  access,
  ConvenientSecurityError,
  DEFAULT_BRIDGE_PATH,
  DeniedError,
  type AccessOptions,
} from 'convenient-security';

const options: AccessOptions = {
  reason: 'type declaration test',
  ttl: 60,
};

async function typecheckPublicApi(): Promise<void> {
  const values: Record<string, string> = await access(['op://demo/key'], options);
  const path: string = DEFAULT_BRIDGE_PATH;
  const error: ConvenientSecurityError = new DeniedError();
  const code: string | undefined = error.code;

  void values;
  void path;
  void code;
}

void typecheckPublicApi;

// @ts-expect-error ttl is expressed in seconds as a number.
void access(['op://demo/key'], { reason: 'invalid type fixture', ttl: '60' });
