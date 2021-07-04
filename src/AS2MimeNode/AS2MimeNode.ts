import { Readable } from 'stream'
import * as MimeNode from 'nodemailer/lib/mime-node'
import { AS2MimeNodeOptions } from './Interfaces'
import {
  isNullOrUndefined,
  signingOptions,
  encryptionOptions,
  isSMime
} from '../Helpers'
import {
  AS2Crypto,
  SigningOptions,
  EncryptionOptions,
  DecryptionOptions,
  VerificationOptions
} from '../AS2Crypto'
import { hostname } from 'os'

/** Class for describing and constructing a MIME document. */
export interface AS2MimeNode {
  keepBcc: boolean
  _headers: Array<{
    key: string 
    value: string
  }>
  filename: string | undefined
  date: Date
  boundaryPrefix: string | undefined
  content: string | Buffer | Readable
  contentType: string | undefined
  rootNode: AS2MimeNode
  parentNode?: AS2MimeNode
  childNodes: AS2MimeNode[]
  nodeCounter: number
  raw: string
  normalizeHeaderKey: Function
  _handleContentType(structured: any): void
  _encodeWords(value: string): string
  _encodeHeaderValue(key: string, value: string): string
}

/** Class for describing and constructing a MIME document. */
export class AS2MimeNode extends MimeNode {
  constructor (options: AS2MimeNodeOptions) {

    super(options?.contentType, { filename: options?.filename, baseBoundary: options?.baseBoundary })

    const {
      filename,
      content,
      baseBoundary,
      boundaryPrefix,
      contentType,
      contentDisposition,
      messageId,
      headers,
      sign,
      encrypt
    } = options


    this.contentType = contentType
    this.boundaryPrefix = boundaryPrefix || '--LibAs2'

    // if (!isNullOrUndefined(content)) this.setContent(content)
    // if (!isNullOrUndefined(headers)) this.setHeader(headers)
    // if (!isNullOrUndefined(sign)) this.setSigning(sign)
    // if (!isNullOrUndefined(encrypt)) this.setEncryption(encrypt)
    // if (!isNullOrUndefined(messageId)) this.setHeader('Message-ID', messageId)
    // if (
    //   !isNullOrUndefined(contentDisposition) &&
    //   contentDisposition !== false
    // ) {
    //   this.setHeader(
    //     'Content-Disposition',
    //     contentDisposition === true ? 'attachment' : contentDisposition
    //   )
    // }
    if (this.contentType) {
      this.signed = contentType?.toLowerCase()?.startsWith('multipart/signed')
      this.encrypted = contentType?.toLowerCase()?.startsWith('multipart/encrypted')
      this.smime = isSMime(contentType?.toLowerCase() || '') || false
      // this.smime = 
      this.compressed = false
      if (this.smime) {
        let applicationType: string = ''

        const parts = contentType?.split(/;/gu) || []

        for (let part of parts) {
          let [key, value] = part.trim().split(/=/gu)
          key = key.trim().toLowerCase()

          if (key === 'smime-type') {
            this.smimeType = value.trim().toLowerCase()
          }

          if (key.startsWith('application/')) {
            applicationType = key
          }
        }

        // Infer smime-type
        if (!this.smimeType || this.smimeType === '') {
          if (applicationType.endsWith('signature')) {
            this.smimeType = 'signed-data'
          } else {
            this.smimeType = 'not-available'
          }
        }

        if (this.smimeType === 'signed-data') this.signed = true
        if (this.smimeType === 'enveloped-data') this.encrypted = true
        if (this.smimeType === 'compressed-data') this.compressed = true
      }
    }

    this.parsed = false
  }

  private _sign: SigningOptions = {} as SigningOptions
  private _encrypt: EncryptionOptions = {} as EncryptionOptions
  parsed: boolean = false
  smime: boolean = false
  signed?: boolean = false
  encrypted?: boolean = false
  compressed?: boolean = false
  smimeType: string = ''

  setSigning (options: SigningOptions): void {
    this._sign = signingOptions(options)
  }

  setEncryption (options: EncryptionOptions): void {
    this._encrypt = encryptionOptions(options)
  }

  setHeader (keyOrHeaders: any, value?: any): this {
    return super.setHeader(keyOrHeaders, value)
  }

  messageId (create: boolean = false) {
    let messageId = this.getHeader('Message-ID')

    // You really should define your own Message-Id field!
    if (!messageId && create) {
      messageId = AS2MimeNode.generateMessageId()

      this.setHeader('Message-ID', messageId)
    }

    return messageId
  }

  async sign (options?: SigningOptions): Promise<AS2MimeNode> {
    options = isNullOrUndefined(options) ? this._sign : options || {} as SigningOptions

    return AS2Crypto.sign(this, options)
  }

  async verify (options: VerificationOptions): Promise<AS2MimeNode|undefined> {
    return (await AS2Crypto.verify(this, options))
      ? this.childNodes[0]
      : undefined
  }

  async decrypt (options: DecryptionOptions): Promise<AS2MimeNode> {
    return AS2Crypto.decrypt(this, options)
  }

  async encrypt (options?: EncryptionOptions): Promise<AS2MimeNode> {
    options = isNullOrUndefined(options) ? this._encrypt : options || {} as EncryptionOptions

    return AS2Crypto.encrypt(this, options)
  }

  async build (): Promise<Buffer> {
    if (this.parsed && this.raw !== undefined) return Buffer.from(this.raw)

    if (!isNullOrUndefined(this._sign) && !isNullOrUndefined(this._encrypt)) {
      const signed = await this.sign(this._sign)
      const encrypted = await signed.encrypt(this._encrypt)

      return await encrypted.build()
    }

    if (!isNullOrUndefined(this._sign)) {
      const signed = await this.sign(this._sign)

      return await signed.build()
    }

    if (!isNullOrUndefined(this._encrypt)) {
      const encrypted = await this.encrypt(this._encrypt)

      return await encrypted.build()
    }

    return await super.build()
  }

  static generateMessageId (sender?: string, uniqueId?: string): string {
    uniqueId = isNullOrUndefined(uniqueId)
      ? AS2Crypto.generateUniqueId()
      : uniqueId
    sender = isNullOrUndefined(uniqueId) ? hostname() || 'localhost' : sender

    return '<' + uniqueId + '@' + sender + '>'
  }
}