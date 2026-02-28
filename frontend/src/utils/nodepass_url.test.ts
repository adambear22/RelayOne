import { buildNodepassURL, PRESETS, type NodepassParams } from './nodepass_url'

describe('buildNodepassURL', () => {
  test('buildNodepassURL 与后端 BuildURL 输出一致', () => {
    const params: NodepassParams = {
      instanceType: 'tcp',
      host: 'example.com',
      port: 8080,
      user: 'alice',
      pass: 'secret',
      tls: 2,
      mode: 'safe',
      min: 16,
      max: 2048,
      rate: 15,
      noTCP: true,
      noUDP: false,
      log: 'info',
    }

    const got = buildNodepassURL(params)
    const want =
      'tcp://alice:secret@example.com:8080?log=info&max=2048&min=16&mode=safe&notcp=1&rate=15&tls=2'

    expect(got).toBe(want)
  })

  test('默认值不写入 query string', () => {
    const got = buildNodepassURL({
      instanceType: 'tcp',
      host: '127.0.0.1',
      port: 7000,
      tls: 1,
      mode: 'fast',
      min: 8,
      max: 1024,
      rate: 0,
      noTCP: false,
      noUDP: false,
      log: 'warn',
    })

    expect(got).toBe('tcp://127.0.0.1:7000')
    expect(got.includes('?')).toBe(false)
  })

  test('预设参数正确填充', () => {
    expect(PRESETS.streaming).toMatchObject({
      tls: 1,
      mode: 'fast',
      min: 32,
      max: 4096,
    })
    expect(PRESETS.low_latency_gaming).toMatchObject({
      noTCP: true,
      noUDP: false,
    })
    expect(PRESETS.secure_transfer).toMatchObject({
      tls: 2,
      mode: 'safe',
      rate: 300,
    })
    expect(PRESETS.ssh_tunnel).toMatchObject({
      mode: 'mix',
      noUDP: true,
    })
  })
})
