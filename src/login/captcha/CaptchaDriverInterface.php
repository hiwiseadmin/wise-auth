<?php
declare(strict_types=1);

namespace wise\login\captcha;

/**
 * 验证码驱动接口
 *
 * 实现：
 *  - GdCaptchaDriver：基于 GD 库生成图片
 *  - BehaviorCaptchaDriver：行为验证码（极验等）占位
 */
interface CaptchaDriverInterface
{
    /**
     * 生成验证码
     *
     * @return array{image:string, key:string, mime:string, expire:int, extra?:array}
     *   - image:  base64 编码的 data URI（data:image/png;base64,xxx）
     *   - key:    验证码存储键（写入 session/cache，用于 verify 校验）
     *   - mime:   图片 mime
     *   - expire: 过期时间戳
     *   - extra:  驱动特有的额外数据（如 BehaviorCaptchaDriver 的 geetest_id）
     *
     * 注意：code 字段已从返回值中移除（SEC-3 修复），验证码文本仅存储在缓存中
     */
    public function generate(): array;

    /**
     * 校验用户输入
     *
     * @param string $key    generate() 返回的 key
     * @param string $input  用户输入
     * @return bool
     */
    public function verify(string $key, string $input): bool;

    /**
     * 获取驱动名称
     */
    public function getName(): string;
}
