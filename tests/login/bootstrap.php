<?php
/**
 * 单元测试引导脚本
 *
 * 单元测试不依赖 ThinkPHP 容器，对 think\Exception 和 think\facade\Cache 创建 stub 类即可。
 */

if (!class_exists('think\\Exception', false)) {
    eval('namespace think; class Exception extends \Exception {}');
}

if (!class_exists('think\\facade\\Cache', false)) {
    eval(<<<'STUB'
namespace think\facade;
class Cache
{
    protected static array $store = [];

    public static function has(string $key): bool
    {
        if (!isset(self::$store[$key])) {
            return false;
        }
        if (self::$store[$key]['expire'] > 0 && self::$store[$key]['expire'] < time()) {
            unset(self::$store[$key]);
            return false;
        }
        return true;
    }

    public static function get(string $key, $default = null)
    {
        if (!self::has($key)) {
            return $default;
        }
        return self::$store[$key]['value'];
    }

    public static function set(string $key, $value, ?int $ttl = null): bool
    {
        self::$store[$key] = [
            'value'  => $value,
            'expire' => $ttl !== null ? time() + $ttl : 0,
        ];
        return true;
    }

    public static function delete(string $key): bool
    {
        unset(self::$store[$key]);
        return true;
    }

    public static function clear(): void
    {
        self::$store = [];
    }
}
STUB
    );
}

if (!function_exists('config')) {
    /**
     * ThinkPHP config() 助手桩（支持点号取值）
     */
    function config(string $key = '', mixed $default = null): mixed
    {
        $items = $GLOBALS['__think_config'] ?? [];

        if ($key === '') {
            return $items;
        }

        $value = $items;
        foreach (explode('.', $key) as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                return $default;
            }
            $value = $value[$segment];
        }

        return $value;
    }
}

require __DIR__ . '/../src/ip/CidrMatcher.php';
require __DIR__ . '/../src/totp/Base32.php';
require __DIR__ . '/../src/contract/TotpUserInterface.php';
require __DIR__ . '/../src/totp/TotpManager.php';
require __DIR__ . '/../src/device/DeviceFingerprint.php';
require __DIR__ . '/../src/totp/BackupCodeManager.php';
require __DIR__ . '/../src/exception/LoginException.php';
require __DIR__ . '/../src/exception/IpBlockedException.php';
require __DIR__ . '/../src/exception/AccountLockedException.php';
require __DIR__ . '/../src/exception/CaptchaInvalidException.php';
require __DIR__ . '/../src/exception/TwoFactorRequiredException.php';
require __DIR__ . '/../src/exception/BackupCodeInvalidException.php';
require __DIR__ . '/../src/exception/TotpUserInterfaceException.php';
require __DIR__ . '/../src/exception/DeviceException.php';
