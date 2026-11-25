<?php
declare(strict_types=1);

namespace wise\login\device;

use wise\support\context\ContextualLogger;

/**
 * 设备指纹生成器
 *
 * 哈希源：
 *   - User-Agent
 *   - 可选：Accept-Language、Accept-Encoding
 *   - 盐值（config 中的 fingerprint_salt）
 *
 * 注意：IP 不再纳入指纹计算（SEC-4 修复），仅作为审计字段在 DeviceManager 中记录。
 * 原因：动态 IP 环境下，IP 变更会导致同一设备频繁产生"新设备"误判。
 */
class DeviceFingerprint
{
    /**
     * 默认弱盐值，用于检测是否未修改配置
     */
    protected const DEFAULT_SALT = 'change-me-to-random-string';

    public function __construct(protected string $salt = '')
    {
        if ($salt === '' || $salt === self::DEFAULT_SALT) {
            ContextualLogger::warning(
                'DeviceFingerprint: 使用默认指纹盐值不安全，请在配置 wise-login-security.device_management.fingerprint_salt 中设置随机字符串'
            );
        }
    }

    /**
     * 从请求参数生成设备指纹
     *
     * @param array  $server     $_SERVER 数组
     * @param string $ip         客户端 IP（仅作为审计字段，不参与指纹计算）
     * @param string $salt       指纹盐值
     * @param bool   $trustProxy 是否信任代理头
     * @return string sha256 指纹（64 字符 hex）
     */
    public static function fromRequest(array $server, string $ip, string $salt = '', bool $trustProxy = true): string
    {
        $ua = (string) ($server['HTTP_USER_AGENT'] ?? '');
        $al = (string) ($server['HTTP_ACCEPT_LANGUAGE'] ?? '');
        $ae = (string) ($server['HTTP_ACCEPT_ENCODING'] ?? '');

        $raw = implode('|', [
            'ua=' . $ua,
            'al=' . $al,
            'ae=' . $ae,
            'salt=' . $salt,
        ]);

        return hash('sha256', $raw);
    }

    /**
     * 给定原始值生成指纹（用于测试）
     *
     * @param string $userAgent      User-Agent 字符串
     * @param string $ip             客户端 IP（仅作为审计字段，不参与指纹计算）
     * @param string $acceptLanguage Accept-Language 头
     * @param string $acceptEncoding Accept-Encoding 头
     * @return string sha256 指纹（64 字符 hex）
     */
    public function generate(string $userAgent, string $ip, string $acceptLanguage = '', string $acceptEncoding = ''): string
    {
        $raw = implode('|', [
            'ua=' . $userAgent,
            'al=' . $acceptLanguage,
            'ae=' . $acceptEncoding,
            'salt=' . $this->salt,
        ]);
        return hash('sha256', $raw);
    }

    /**
     * 设置指纹盐值
     *
     * @param string $salt 新的盐值
     * @return void
     */
    public function setSalt(string $salt): void
    {
        $this->salt = $salt;
    }
}
