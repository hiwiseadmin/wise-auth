<?php
declare(strict_types=1);

namespace wise\login\twofactor;

use wise\login\contract\TotpUserInterface;

/**
 * 双因素认证驱动接口＼�
 *
 * 除 TOTP 外，支持 SMS/Email 等多渠道 2FA。
 * 每个驱动负责：发送验证码 + 校验验证码。
 *
 * 使用方式：
 *  - TwoFactorMiddleware 根据配置 preferred_method 选择驱动
 *  - 或用户登录后选择自己偏好的 2FA 方式
 */
interface TwoFactorDriverInterface
{
    /**
     * 获取驱动名称
     */
    public function getName(): string;

    /**
     * 发送验证码
     *
     * @param TotpUserInterface $user   目标用户
     * @param string            $target 发送目标（邮箱地址/手机号等）
     * @return array{success: bool, error?: string} 发送结果
     */
    public function sendCode(TotpUserInterface $user, string $target): array;

    /**
     * 校验验证码
     *
     * @param TotpUserInterface $user  目标用户
     * @param string            $code  用户输入的验证码
     * @return bool 是否通过
     */
    public function verify(TotpUserInterface $user, string $code): bool;

    /**
     * 是否允许受信任设备跳过此 2FA 方式
     *
     * SMS/Email 通常允许跳过（避免频繁打扰），TOTP 可选跳过。
     */
    public function skipForTrustedDevice(): bool;

    /**
     * 验证码有效期（秒）
     */
    public function codeTtl(): int;

    /**
     * 验证码长度（位数）
     */
    public function codeLength(): int;
}
