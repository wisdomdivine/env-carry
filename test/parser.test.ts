import { describe, it, expect } from 'vitest';
import { parseEnv, stringifyEnv } from '../src/parser.js';

describe('parser module', () => {
  it('parses typical .env lines correctly', () => {
    const raw = `
# Server config
PORT=3000
HOST="localhost"
MESSAGE='Hello World'
export NODE_ENV=production

# Database
DATABASE_URL=postgres://root:secret@127.0.0.1:5432/app # inline db comment
EMPTY_VAR=
`;
    const parsed = parseEnv(raw);
    expect(parsed.map.PORT).toBe('3000');
    expect(parsed.map.HOST).toBe('localhost');
    expect(parsed.map.MESSAGE).toBe('Hello World');
    expect(parsed.map.NODE_ENV).toBe('production');
    expect(parsed.map.DATABASE_URL).toBe('postgres://root:secret@127.0.0.1:5432/app');
    expect(parsed.map.EMPTY_VAR).toBe('');
  });

  it('stringifies map to clean .env string', () => {
    const map = {
      API_KEY: 'test1234',
      MESSAGE: 'Hello Space',
      PORT: '8080'
    };
    const stringified = stringifyEnv(map);
    expect(stringified).toContain('API_KEY=test1234');
    expect(stringified).toContain('MESSAGE="Hello Space"');
    expect(stringified).toContain('PORT=8080');
  });
});
