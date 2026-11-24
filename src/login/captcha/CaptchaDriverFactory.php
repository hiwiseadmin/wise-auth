<?php
declare(strict_types=1);

namespace wise\login\captcha;

use think\App;

/**
 * 验证码驱动工厂
 *
 * 根据配置 driver 创建对应实例
 * 内置驱动：gd / geetest
 * 自定义驱动：实现 CaptchaDriverInterface 后调用 CaptchaDriverFactory::extend() 注册
 */
class CaptchaDriverFactory
{
    /** @var array<string, class-string<CaptchaDriverInterface>> */
    protected static array $map = [
        'gd'       => GdCaptchaDriver::class,
        'geetest'  => GeetestV4CaptchaDriver::class,
        'tencent'  => TencentCaptchaDriver::class,
        'hcaptcha' => HcaptchaDriver::class,
    ];

    /**
     * 根据名称创建对应驱动实例
     *
     * @param string $name 驱动名（gd / geetest / tencent / hcaptcha）
     * @param App    $app  应用实例
     * @return CaptchaDriverInterface
     * @throws \InvalidArgumentException 未知驱动时抛出
     */
    public static function create(string $name, App $app): CaptchaDriverInterface
    {
        $name = strtolower($name);
        if (!isset(self::$map[$name])) {
            throw new \InvalidArgumentException("Unknown captcha driver: {$name}");
        }
        $class = self::$map[$name];
        return new $class($app);
    }

    /**
     * 注册自定义驱动
     */
    public static function extend(string $name, string $class): void
    {
        if (!is_subclass_of($class, CaptchaDriverInterface::class)) {
            throw new \InvalidArgumentException("{$class} must implement " . CaptchaDriverInterface::class);
        }
        self::$map[strtolower($name)] = $class;
    }
}
