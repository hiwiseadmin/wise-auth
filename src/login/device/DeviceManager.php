<?php
declare(strict_types=1);

namespace wise\login\device;

use think\facade\Db;
use wise\support\context\ContextualLogger;
use wise\login\event\EventLogger;
use wise\login\exception\DeviceException;
use wise\login\ip\CidrMatcher;
use wise\login\model\UserDevice;

/**
 * 设备管理器
 *
 * 职责：
 *  - 登录时记录设备
 *  - 检查设备是否已信任
 *  - 信任 / 撤销 / 重命名
 *  - 列出用户所有设备
 */
class DeviceManager
{
    public function __construct(protected EventLogger $eventLogger)
    {
    }

    /**
     * 记录 / 更新设备
     *
     * - 已存在（fingerprint 匹配）→ 更新 last_used_at
     * - 不存在 → 插入新行
     *
     * @return array{device: UserDevice, isNew: bool, isTrusted: bool}
     */
    public function record(int $userId, array $server, ?string $deviceName = null, bool $trustNew = false): array
    {
        $cfg = config('wise-auth.login.device_management', []);
        $salt = (string) ($cfg['fingerprint_salt'] ?? '');
        $trustProxy = (bool) ($cfg['trust_proxy_header'] ?? true);

        $trustedProxies = (array) config('wise-auth.login.ip_list.trusted_proxies', []);
        $ip = CidrMatcher::getClientIp($server, $trustProxy, $trustedProxies);
        $fingerprint = DeviceFingerprint::fromRequest($server, $ip, $salt, $trustProxy);

        if ($salt === '' || $salt === 'change-me-to-random-string') {
            ContextualLogger::warning(
                'DeviceManager: 使用默认指纹盐值不安全，请在配置 wise-login-security.device_management.fingerprint_salt 中设置随机字符串'
            );
        }

        $device = UserDevice::where('user_id', $userId)
            ->where('device_fingerprint', $fingerprint)
            ->find();

        $isNew = false;
        if (!$device) {
            $device = new UserDevice();
            $device->user_id = $userId;
            $device->device_fingerprint = $fingerprint;
            $device->is_trusted = $trustNew ? 1 : 0;
            $isNew = true;
        } else {
            $device->is_trusted = $device->is_trusted ?? 0;
        }

        $device->ip = $ip;
        $device->user_agent = substr((string) ($server['HTTP_USER_AGENT'] ?? ''), 0, 500);
        $device->device_name = $deviceName ?: ($device->device_name ?: $this->guessDeviceName($server));
        $device->last_used_at = time();
        $device->save();

        if ($isNew && (bool) ($cfg['notify_new_device'] ?? true)) {
            $this->eventLogger->log('device_new', [
                'user_id'    => $userId,
                'device_id'  => $device->id,
                'ip'         => $ip,
                'user_agent' => $device->user_agent,
            ]);
        }

        return [
            'device'    => $device,
            'isNew'     => $isNew,
            'isTrusted' => (int) $device->is_trusted === 1,
        ];
    }

    /**
     * 信任设备
     */
    public function trust(int $userId, int $deviceId, int $days = 30): UserDevice
    {
        $device = UserDevice::where('user_id', $userId)->where('id', $deviceId)->find();
        if (!$device) {
            throw new DeviceException('设备不存在', ['device_id' => $deviceId]);
        }
        $device->is_trusted = 1;
        $device->trusted_at = time();
        $device->trust_expire_at = time() + $days * 86400;
        $device->save();

        $this->eventLogger->log('device_trusted', [
            'user_id'    => $userId,
            'device_id'  => $device->id,
            'days'       => $days,
            'user_agent' => $device->user_agent ?? null,
        ]);
        return $device;
    }

    /**
     * 撤销（删除）设备
     */
    public function revoke(int $userId, int $deviceId): bool
    {
        $device = UserDevice::where('user_id', $userId)->where('id', $deviceId)->find();
        if (!$device) {
            return false;
        }
        $userAgent = $device->user_agent ?? null;
        $device->delete();

        $this->eventLogger->log('device_revoked', [
            'user_id'    => $userId,
            'device_id'  => $deviceId,
            'user_agent' => $userAgent,
        ]);
        return true;
    }

    /**
     * 重命名设备
     */
    public function rename(int $userId, int $deviceId, string $name): UserDevice
    {
        $device = UserDevice::where('user_id', $userId)->where('id', $deviceId)->find();
        if (!$device) {
            throw new DeviceException('设备不存在', ['device_id' => $deviceId]);
        }
        $device->device_name = mb_substr($name, 0, 50);
        $device->save();
        return $device;
    }

    /**
     * 检查设备是否在信任期内
     */
    public function isTrusted(int $userId, array $server): bool
    {
        $cfg = config('wise-auth.login.device_management', []);
        $salt = (string) ($cfg['fingerprint_salt'] ?? '');
        $trustProxy = (bool) ($cfg['trust_proxy_header'] ?? true);

        $trustedProxies = (array) config('wise-auth.login.ip_list.trusted_proxies', []);
        $ip = CidrMatcher::getClientIp($server, $trustProxy, $trustedProxies);
        $fingerprint = DeviceFingerprint::fromRequest($server, $ip, $salt, $trustProxy);

        $device = UserDevice::where('user_id', $userId)
            ->where('device_fingerprint', $fingerprint)
            ->where('is_trusted', 1)
            ->find();

        if (!$device) {
            return false;
        }

        $expire = (int) ($device->trust_expire_at ?? 0);
        if ($expire > 0 && $expire < time()) {
            return false;
        }

        return true;
    }

    /**
     * 列出用户所有设备
     */
    public function listForUser(int $userId): array
    {
        return UserDevice::where('user_id', $userId)
            ->order('last_used_at', 'desc')
            ->select()
            ->toArray();
    }

    /**
     * 简单推断设备名称（基于 UA 关键字）
     */
    protected function guessDeviceName(array $server): string
    {
        $ua = (string) ($server['HTTP_USER_AGENT'] ?? '');
        if ($ua === '') {
            return 'Unknown Device';
        }
        if (stripos($ua, 'iPhone') !== false)  return 'iPhone';
        if (stripos($ua, 'iPad') !== false)    return 'iPad';
        if (stripos($ua, 'Android') !== false) return 'Android';
        if (stripos($ua, 'Mac OS') !== false)  return 'Mac';
        if (stripos($ua, 'Windows') !== false) return 'Windows PC';
        if (stripos($ua, 'Linux') !== false)   return 'Linux';
        return mb_substr($ua, 0, 30);
    }
}
