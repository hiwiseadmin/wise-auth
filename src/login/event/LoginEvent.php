<?php
declare(strict_types=1);

namespace wise\login\event;

/**
 * 登录安全事件（ThinkPHP 事件驱动）
 *
 * 通过 ThinkPHP 的 event() 触发，监听器可监听 wise\login\event\LoginEvent
 *
 * 事件类型常量见 LoginEvent::TYPE_*
 */
class LoginEvent
{
    public const TYPE_LOGIN_FAILURE     = 'login_failure';
    public const TYPE_LOGIN_SUCCESS     = 'login_success';
    public const TYPE_ACCOUNT_LOCKED    = 'account_locked';
    public const TYPE_ACCOUNT_UNLOCKED  = 'account_unlocked';
    public const TYPE_IP_BLACKLISTED    = 'ip_blacklisted';
    public const TYPE_CAPTCHA_FAILED    = 'captcha_failed';
    public const TYPE_TOTP_VERIFIED     = 'totp_verified';
    public const TYPE_TOTP_FAILED       = 'totp_failed';
    public const TYPE_DEVICE_TRUSTED    = 'device_trusted';
    public const TYPE_DEVICE_NEW        = 'device_new';
    public const TYPE_DEVICE_REVOKED    = 'device_revoked';

    /**
     * @param string $eventType 事件类型（TYPE_* 常量）
     * @param array  $data      业务数据
     * @param string $username  关联用户名
     * @param string $ip        关联 IP
     * @param string $userAgent 关联 UA
     */
    public function __construct(
        public string $eventType,
        public array $data = [],
        public ?string $username = null,
        public ?string $ip = null,
        public ?string $userAgent = null
    ) {
    }

    public function getEventType(): string
    {
        return $this->eventType;
    }

    public function getData(): array
    {
        return $this->data;
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function getIp(): ?string
    {
        return $this->ip;
    }
}
