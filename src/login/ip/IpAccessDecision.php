<?php
declare(strict_types=1);

namespace wise\login\ip;

/**
 * IP 访问判定（唯一实现）
 *
 * 背景：同一份「黑白名单 + mode」判定曾在两处各写一份 ——
 *   - {@see \wise\login\middleware\IpGuardMiddleware}（admin 应用门禁）
 *   - {@see \wise\login\action\IpGuardAction}（登录守卫管道）
 * 两处语义必须完全一致，但文案与分支各写一遍，改一处漏一处就会漂移
 * （例：白名单优先逻辑只改了中间件，登录链路仍按旧顺序拦截）。
 *
 * 这里把「怎么判」收敛为一处；两处调用方只负责「怎么拦/怎么记」：
 *   - 中间件：拒绝时写事件表 + 注入 X-Real-Client-Ip
 *   - Action：拒绝时写登录尝试链（联动失败计数/锁定/验证码）
 *
 * 判定顺序（白名单优先，与改造前一致）：
 *   1. mode ∈ {whitelist, both} 且命中白名单 → 放行
 *   2. mode = whitelist 且未命中 → 拒绝（not_in_whitelist）
 *   3. mode ∈ {blacklist, both} 且命中黑名单 → 拒绝（blacklist）
 *   4. 其余 → 放行
 */
final class IpAccessDecision
{
    public const MODE_BLACKLIST = 'blacklist';
    public const MODE_WHITELIST = 'whitelist';
    public const MODE_BOTH      = 'both';

    /** 白名单命中放行 */
    public const REASON_WHITELIST = 'whitelist';

    /** whitelist 模式下未命中白名单 */
    public const REASON_NOT_IN_WHITELIST = 'not_in_whitelist';

    /** 命中黑名单 */
    public const REASON_BLACKLIST = 'blacklist';

    /** 未命中任何名单，按默认放行 */
    public const REASON_DEFAULT = 'default';

    /** @var string[] CIDR 黑名单 */
    private array $blacklist;

    /** @var string[] CIDR 白名单 */
    private array $whitelist;

    private string $mode;

    /**
     * @param string[] $blacklist CIDR 黑名单
     * @param string[] $whitelist CIDR 白名单
     * @param string   $mode      blacklist | whitelist | both
     * @throws \InvalidArgumentException 非法 mode
     */
    public function __construct(
        array $blacklist = [],
        array $whitelist = [],
        string $mode = self::MODE_BLACKLIST
    ) {
        if (!in_array($mode, [self::MODE_BLACKLIST, self::MODE_WHITELIST, self::MODE_BOTH], true)) {
            throw new \InvalidArgumentException(
                "Invalid IP guard mode: [{$mode}], expected 'blacklist', 'whitelist', or 'both'"
            );
        }

        $this->blacklist = $blacklist;
        $this->whitelist = $whitelist;
        $this->mode      = $mode;
    }

    /**
     * 判定某个 IP 是否允许访问
     *
     * @param string $ip IPv4 / IPv6
     * @return array{allowed: bool, reason: string, whitelist_hit: bool}
     *   reason 取值见 REASON_* 常量，供调用方决定日志文案（避免文案与判定耦合）
     */
    public function evaluate(string $ip): array
    {
        $whitelistEnabled = in_array($this->mode, [self::MODE_WHITELIST, self::MODE_BOTH], true);

        if ($whitelistEnabled && CidrMatcher::match($ip, $this->whitelist)) {
            return [
                'allowed'       => true,
                'reason'        => self::REASON_WHITELIST,
                'whitelist_hit' => true,
            ];
        }

        if ($this->mode === self::MODE_WHITELIST) {
            return [
                'allowed'       => false,
                'reason'        => self::REASON_NOT_IN_WHITELIST,
                'whitelist_hit' => false,
            ];
        }

        $blacklistEnabled = in_array($this->mode, [self::MODE_BLACKLIST, self::MODE_BOTH], true);

        if ($blacklistEnabled && CidrMatcher::match($ip, $this->blacklist)) {
            return [
                'allowed'       => false,
                'reason'        => self::REASON_BLACKLIST,
                'whitelist_hit' => false,
            ];
        }

        return [
            'allowed'       => true,
            'reason'        => self::REASON_DEFAULT,
            'whitelist_hit' => false,
        ];
    }
}
