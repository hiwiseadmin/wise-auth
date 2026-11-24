<?php
declare(strict_types=1);

namespace wise\login\totp;

use think\facade\Cache;
use wise\login\contract\TotpUserInterface;
use wise\login\exception\TotpUserInterfaceException;

/**
 * TOTP（RFC 6238）管理器
 *
 * 纯 PHP 实现，支持 sha1 / sha256 / sha512
 * 提供：
 *  - generateSecret(): 生成随机 Base32 密钥
 *  - getQrUri(): 生成 otpauth:// URI（配合 Google Authenticator 等）
 *  - getQrDataUri(): 生成可嵌入 <img> 的 base64 SVG / PNG URI
 *  - verify($user, $code): 校验 6 位动态码（含重放保护）
 */
class TotpManager
{
    public function __construct(protected array $config = [])
    {
        $this->config = array_merge([
            'issuer'        => 'WiseAdmin',
            'digits'        => 6,
            'period'        => 30,
            'algorithm'     => 'sha1',
            'secret_length' => 20,
        ], $config);
    }

    /** @return int TOTP 码位数 */
    public function getDigits(): int
    {
        return (int) $this->config['digits'];
    }

    /** @return int TOTP 时间步长（默认 30 秒） */
    public function getPeriod(): int
    {
        return (int) $this->config['period'];
    }

    /** @return string 哈希算法：sha1 | sha256 | sha512 */
    public function getAlgorithm(): string
    {
        $algo = strtolower((string) $this->config['algorithm']);
        return in_array($algo, ['sha1', 'sha256', 'sha512'], true) ? $algo : 'sha1';
    }

    /**
     * 生成随机 Base32 密钥
     */
    public function generateSecret(): string
    {
        $len = (int) $this->config['secret_length'];
        return Base32::encode(random_bytes(max(8, $len)));
    }

    /**
     * 生成 otpauth URI（用于 QR 码内容）
     */
    public function getQrUri(TotpUserInterface $user): string
    {
        $secret = $user->getTotpSecret();
        if (!$secret) {
            throw new TotpUserInterfaceException('User has no TOTP secret');
        }

        $label = rawurlencode($this->config['issuer'] . ':' . $user->getTotpLabel());
        $params = http_build_query([
            'secret'    => $secret,
            'issuer'    => $this->config['issuer'],
            'algorithm' => strtoupper($this->getAlgorithm()),
            'digits'    => $this->getDigits(),
            'period'    => $this->getPeriod(),
        ]);

        return "otpauth://totp/{$label}?{$params}";
    }

    /**
     * 生成 QR 码 data URI
     *
     * 优先使用 wise-qrcode 包生成真实可扫描的 PNG 二维码；
     * 未安装/生成失败时退回内置占位 SVG（仅展示 otpauth URI 文本，不可扫描）。
     */
    public function getQrDataUri(TotpUserInterface $user, int $size = 200): string
    {
        $uri = $this->getQrUri($user);

        if (class_exists(\wise\qrcode\facade\Qrcode::class)) {
            try {
                return \wise\qrcode\facade\Qrcode::toDataUri($uri);
            } catch (\Throwable $e) {
            }
        }

        $svg = $this->buildQrSvg($uri, $size);
        return 'data:image/svg+xml;base64,' . base64_encode($svg);
    }

    /**
     * 校验 TOTP 码
     *
     * SEC-6 修复：新增重放保护 — 验证成功后缓存已使用的码（key 为 secret_hash + timestep），
     * 同一 TOTP 码在同一时间窗口内不可被多次使用，TTL 为 2 个 period
     *
     * @param TotpUserInterface $user  用户接口
     * @param string            $code  用户输入的 TOTP 码
     * @param int               $window 容忍窗口（前后各 N 个时间步）
     * @return bool 是否验证通过
     */
    public function verify(TotpUserInterface $user, string $code, int $window = 1): bool
    {
        $secret = $user->getTotpSecret();
        if (!$secret) {
            return false;
        }
        $code = preg_replace('/\s+/', '', $code) ?? '';
        if ($code === '' || !preg_match('/^\d{' . $this->getDigits() . '}$/', $code)) {
            return false;
        }

        $timestep = (int) floor(time() / $this->getPeriod());
        $secretHash = hash('sha256', $secret);

        for ($i = -$window; $i <= $window; $i++) {
            $step = $timestep + $i;
            $candidate = $this->generateAt($secret, $step);
            if (hash_equals($candidate, $code)) {
                $replayKey = 'wise_login_security:totp_replay:' . $secretHash . ':' . $step;
                if (!$this->claimReplayKey($replayKey, $this->getPeriod() * 2)) {
                    return false;
                }
                return true;
            }
        }
        return false;
    }

    /**
     * 在指定时间步生成 TOTP
     */
    public function generateAt(string $secretBase32, int $timestep): string
    {
        $key = Base32::decode($secretBase32);
        $timeBytes = pack('N*', 0, $timestep);
        $hash = hash_hmac($this->getAlgorithm(), $timeBytes, $key, true);
        $offset = ord($hash[strlen($hash) - 1]) & 0xF;

        $binary = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        );

        $code = $binary % (10 ** $this->getDigits());
        return str_pad((string) $code, $this->getDigits(), '0', STR_PAD_LEFT);
    }

    /**
     * 原子占用 TOTP 重放标记
     *
     * Redis 场景使用 SET NX EX，保证并发下同一时间步只有一个请求能占用成功；
     * 其他缓存驱动退化为 has() + set()（非原子，但常规串行提交仍能拒绝重放）。
     *
     * @param string $key 重放标记键
     * @param int    $ttl 有效期（秒）
     * @return bool true=占用成功（首次使用），false=已被占用（重放）
     */
    protected function claimReplayKey(string $key, int $ttl): bool
    {
        try {
            $handler = Cache::store('redis')->handler();
            if (is_object($handler) && get_class($handler) === 'Redis') {
                $ok = $handler->set($key, 1, ['nx', 'ex' => $ttl]);
                return $ok !== false && $ok !== null;
            }
        } catch (\Throwable) {
        }

        if (Cache::has($key)) {
            return false;
        }
        Cache::set($key, true, $ttl);
        return true;
    }

    /**
     * 内置占位 SVG 渲染（仅在 wise-qrcode 不可用时兜底）
     *
     * ⚠️ 该 SVG 只展示 otpauth URI 文本，**不可被扫码识别**，仅用于调试/降级展示。
     */
    protected function buildQrSvg(string $uri, int $size): string
    {
        $esc = htmlspecialchars($uri, ENT_XML1 | ENT_QUOTES, 'UTF-8');
        $w = $size;
        $h = $size + 60;
        $w2 = $w - 20;
        $h2 = $h - 40;
        return <<<SVG
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{$w}" height="{$h}" viewBox="0 0 {$w} {$h}">
  <rect x="0" y="0" width="{$w}" height="{$h}" fill="#ffffff" stroke="#cccccc" stroke-width="1"/>
  <text x="10" y="20" font-family="monospace" font-size="11" fill="#999">QR placeholder (use endroid/qr-code in production):</text>
  <foreignObject x="10" y="30" width="{$w2}" height="{$h2}">
    <div xmlns="http://www.w3.org/1999/xhtml" style="font-family:monospace;font-size:9px;word-break:break-all;color:#333;line-height:1.3">{$esc}</div>
  </foreignObject>
</svg>
SVG;
    }
}
