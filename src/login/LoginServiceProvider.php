<?php
declare(strict_types=1);

namespace wise\login;

use think\App;
use think\facade\Config;
use wise\login\captcha\BehaviorCaptchaDriver;
use wise\login\captcha\CaptchaDriverFactory;
use wise\login\captcha\CaptchaDriverInterface;
use wise\login\captcha\GdCaptchaDriver;
use wise\login\captcha\GeetestV4CaptchaDriver;
use wise\login\command\ClearLoginFailures;
use wise\login\command\Recovery;
use wise\login\command\SecurityTest;
use wise\login\command\Unlock;
use wise\login\contract\TotpUserInterface;
use wise\login\device\DeviceFingerprint;
use wise\login\device\DeviceManager;
use wise\login\event\EventLogger;
use wise\login\ip\ConfigIpListProvider;
use wise\login\ip\DatabaseIpListProvider;
use wise\login\ip\IpListProviderInterface;
use wise\login\lock\CacheFailedAttemptStore;
use wise\login\lock\DatabaseFailedAttemptStore;
use wise\login\lock\FailedAttemptStoreInterface;
use wise\login\lock\LoginLockManager;
use wise\login\lock\RedisFailedAttemptStore;
use wise\login\menu\LoginMenuProvider;
use wise\login\totp\BackupCodeManager;
use wise\login\totp\RecoveryCodeManager;
use wise\login\totp\TotpManager;
use wise\support\ExtPoint;
use wise\support\ExtPoints;
use wise\support\contracts\EnvSeedProvider;
use wise\support\config\ConfigCheckCollector;
use wise\login\config\LoginCheck;

/**
 * 登录安全服务注册（独立 service）
 *
 * 通过 composer.json 的 extra.think.services 自动发现，与 `wise\auth\AuthServiceProvider`
 * 各自独立注册（auth 在前、login 在后，配置由 auth 统一 merge）。
 *
 * 职责：
 *  1. 绑定接口 → 默认实现（验证码驱动 / IP 名单 / 失败计数 / 锁 / TOTP / 设备 / 事件）
 *  2. 注册控制台命令
 *  3. 注册路由 / 菜单 / 事件监听器（boot）
 *
 * 迁移目录仍由 AuthServiceProvider 统一注册（两包迁移已平铺到同一 database/migrations）。
 */
class LoginServiceProvider extends \think\Service implements EnvSeedProvider
{
    use \wise\support\traits\ServiceTrait;

    /**
     * 声明需要播种到 .env 的密钥（安装时自动生成，重装不覆盖）
     *
     * WISE_LOGIN_FINGERPRINT_SALT：设备指纹 HMAC 盐值，原配置文件默认
     * 'change-me-to-random-string'，属不安全占位，必须安装时随机生成。
     */
    public static function envSeeds(): array
    {
        return [
            'WISE_LOGIN_FINGERPRINT_SALT' => [
                'type'      => 'secret',
                'generator' => 'hmac_salt',
                'comment'   => '设备指纹 HMAC 盐值（随机生成）',
            ],
        ];
    }

    public function register(): void
    {

        $this->app->make(ConfigCheckCollector::class)->register(
            new LoginCheck($this->app->config)
        );

        $this->app->bind(CaptchaDriverInterface::class, function (App $app) {
            $driver = $app->config->get('wise-auth.login.captcha.driver', 'gd');
            return CaptchaDriverFactory::create($driver, $app);
        });
        $this->app->bind(GdCaptchaDriver::class, GdCaptchaDriver::class);
        $this->app->bind(GeetestV4CaptchaDriver::class, GeetestV4CaptchaDriver::class);

        $this->app->bind(IpListProviderInterface::class, function (App $app) {
            $provider = $app->config->get('wise-auth.login.ip_list.provider', 'config');
            return match ($provider) {
                'database' => new DatabaseIpListProvider(),
                default    => new ConfigIpListProvider($app),
            };
        });

        $this->app->bind(FailedAttemptStoreInterface::class, function (App $app) {
            $store = $app->config->get('wise-auth.login.failed_attempts.store', 'cache');
            $prefix = $app->config->get('wise-auth.login.failed_attempts.cache_prefix', 'wise_login_security:failed:');
            $decayMinutes = (int) $app->config->get('wise-auth.login.failed_attempts.decay_minutes', 60);
            $cacheStore = (string) $app->config->get('wise-auth.login.failed_attempts.cache_store', '');

            return match ($store) {
                'redis'    => new RedisFailedAttemptStore($app, $prefix, $decayMinutes),
                'database' => new DatabaseFailedAttemptStore($app, $prefix, $decayMinutes),
                default    => new CacheFailedAttemptStore($app, $prefix, $decayMinutes, $cacheStore),
            };
        });

        $this->app->bind(LoginLockManager::class, function (App $app) {
            return new LoginLockManager(
                $app,
                $app->make(FailedAttemptStoreInterface::class),
                $app->config->get('wise-auth.login.failed_attempts', [])
            );
        });

        $this->app->bind(TotpManager::class, TotpManager::class);
        $this->app->bind(BackupCodeManager::class, BackupCodeManager::class);
        $this->app->bind(RecoveryCodeManager::class, RecoveryCodeManager::class);

        $this->app->bind(DeviceFingerprint::class, DeviceFingerprint::class);
        $this->app->bind(DeviceManager::class, DeviceManager::class);

        $this->app->bind(EventLogger::class, EventLogger::class);

        $this->commands([
            Unlock::class,
            SecurityTest::class,
            Recovery::class,
            ClearLoginFailures::class,
        ]);
    }

    public function boot(): void
    {
        $this->registerLogChannel();


        if (Config::get('wise-auth.login.route.auto_register', true)) {
            RouteRegistrar::register();
        }
        $this->registerAdminMenu();

        $this->app->event->listen(
            \wise\login\event\LoginEvent::class,
            \wise\login\listener\NewDeviceMailListener::class
        );
        $this->app->event->listen(
            \wise\login\event\LoginEvent::class,
            \wise\login\listener\LockedAccountMailListener::class
        );
    }

    /**
     * 动态注册 wise_login_security 日志通道
     *
     * 将 SMS/Email 2FA 发送失败的专用日志通道注册到框架 log 配置中，
     * 用户无需手动修改 config/log.php。
     * 如果用户已在 log.php 中定义同名通道，则优先使用用户配置。
     */
    protected function registerLogChannel(): void
    {
        $channels = $this->app->config->get('log.channels', []);

        if (!isset($channels['wise_login_security'])) {
            $channels['wise_login_security'] = [
                'type'           => 'File',
                'path'           => runtime_path() . 'log/wise_login_security/',
                'single'         => false,
                'apart_level'    => [],
                'max_files'      => 30,
                'json'           => false,
                'realtime_write' => false,
                'format'         => '[%s][%s] %s',
            ];
            $this->app->config->set(['channels' => $channels], 'log');
        }
    }

    /**
     * 声明后台「安全管理」菜单（ExtPoints::MENU_ITEM）
     *
     * 菜单不硬编码 INSERT，而是在包内 LoginMenuProvider 声明，
     * 由宿主 app\admin\service\MenuItemSync 幂等落库并自动派生权限。
     * 落库执行：`php think menu:sync`（声明变化时后台也会懒同步）。
     */
    protected function registerAdminMenu(): void
    {
        if (!interface_exists(\wise\support\contracts\MenuItemProvider::class)
            || !class_exists(ExtPoint::class)
            || !class_exists(ExtPoints::class)) {
            return;
        }

        try {
            ExtPoint::register(
                ExtPoints::MENU_ITEM,
                'wise-auth.login',
                LoginMenuProvider::class
            );
        } catch (\Throwable $e) {
        }
    }
}
