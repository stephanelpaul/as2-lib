export type AS2Signing = 'sha1' | 'sha256' | 'sha384' | 'sha512'

export type AS2Encryption =
  | 'des-EDE3-CBC'
  | 'aes128-CBC'
  | 'aes192-CBC'
  | 'aes256-CBC'


export interface EncryptionOptions {
    cert: string
    encryption: AS2Encryption
}

export interface DecryptionOptions {
    cert: string
    key: string
}

export interface SigningOptions {
    cert: string
    key: string
    chain?: string[]
    micalg?: AS2Signing
}

export interface VerificationOptions {
    cert: string
    micalg?: AS2Signing
}