<?php
declare(strict_types=1);

namespace wise\login\action;

use Closure;
use think\Request;
use wise\login\contract\LoginGuardAction;
use wise\login\contract\LoginPayload;
use wise\support\context\ContextualLogger;
use wise\support\traits\JsonResponse;

/**
 * 同源校验 Action（登录端点的来源校验）
 *
 * 适用前提（重要）
 * ----------------
 * `wise-login-security` 只负责 **Web 端登录**：登录页由框架自身渲染，
 * 是本系统被访问的第一步，不存在 App / 小程序 / 服务端直调的登录入口。
 *
 * 判定顺序（从严到宽）：
 *
 *   1. `Sec-Fetch-Site: cross-site` → **拒绝**；
 *      `Sec-Fetch-Site: same-site` 默认也拒绝（子域视为不可信），
 *      因为登录页恒为同源提交，出现 same-site 已属异常；
 *   2. `Sec-Fetch-Site: same-origin` → **放行**（见下「为什么信任 Fetch Metadata」），
 *      即使浏览器没有带 `Origin` / `Referer` 也不影响；
 *   3. 任何来源证据都取不到（`Origin` / `Referer` / `Sec-Fetch-Site` 全空）时
 *      **默认放行**（`require_source = false`），防 CSRF 由包内令牌层负责；
 *   4. 取到了来源时，host 必须命中允许列表（默认取请求 Host，生产建议显式配置）；
 *   5. 拒绝时**不回显**允许列表，避免向攻击者泄露内部域名结构。
 *
 * 为什么「缺少来源」不再直接拒绝＼�
 * -----------------------------------------
 * 这一条是**误报的重灾区**，而它带来的安全收益几乎为零：
 *   - 现实里三者会同时为空：企业代理 / 抓包工具 / 隐私扩展会剥掉 `Referer`，
 *     WebView、部分国产浏览器内核、旧版 Safari 对同源 POST 既不写 `Origin`
 *     也不写 `Sec-Fetch-Site`。此时请求完全合法，却被 403 挡在登录门外；
 *   - 登录端点的 CSRF 由 `CsrfTokenMiddleware`（Session 令牌）兜住：
 *     攻击者跨站构造的 POST 拿不到令牌，必然在令牌层被拒。
 *     所以「来源层」只是**纵深防御的加固**，不能反过来成为可用性瓶颈，
 *     更不该在证据缺失（而非证据为恶意）时 fail-closed。
 *   - fail-closed 只保留给「证据明确为恶意」的分支：`cross-site`、
 *     `same-site`（可配）、以及来源 host 不在允许列表。
 *
 * 为什么信任 Fetch Metadata（`Sec-Fetch-Site`）
 * --------------------------------------------
 * 该头由浏览器网络栈写入，属于 Fetch Metadata 保护机制，
 * 页面 JS 无法设置（`Sec-` 前缀在 Fetch 规范中为禁止头），
 * 因此「`same-origin`」与「`Origin` 命中允许列表」是**同等强度**的证据。
 * 真正的跨站请求会先在上面的 `cross-site` 分支被拒绝。
 *
 * 与全局 CSRF 的关系（分层边界，不要合并）
 * ----------------------------------------
 * `config/csrf.php` 的 `except` 显式排除 `admin/login/*`，这是**有意的分层**：
 * 后台登录端点的安全由 `wise-login-security` 自行负责，不使用全局 Cookie 令牌。
 *
 * 登录端点因此有两层包内防线：
 *   ① 令牌层：`CsrfTokenMiddleware`（Session 令牌 `_csrf_token`），挂在
 *      `login/doLogin` 路由；令牌由 `Login::index()` 渲染时下发。
 *   ② 来源层：本 Action（Origin / Referer / Sec-Fetch-Site），位于守卫管道内。
 *
 * 两层互补：令牌是**主防线**（防伪造：攻击者拿不到同源 Session 里的值），
 * 来源层只额外拒绝「已声明为外部来源」的请求，缺证据时让位给令牌层。
 *
 * 为什么不改用全局 CSRF
 * ---------------------
 *   1. 全局层是 Cookie 令牌，业务页面靠 JS 读 Cookie 提交；登录页在未登录状态
 *      渲染，属于另一套生命周期，混用会把两层令牌搅成"A 签发、B 校验"；
 *   2. 本 Action 位于登录守卫管道，可被插件通过
 *      `LoginRegistry::registerGuard()` 扩展，职责更内聚。
 *
 * @package wise\login\action
 */
class SameOriginCheckAction implements LoginGuardAction
{
    use JsonResponse;

    /** 只读方法不做来源校验 */
    protected const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

    /**
     * @param string[] $allowedHosts    允许的来源 host（不含协议，可含端口）。
     *                                  留空 = 取当前请求的 Host（兼容默认部署）。
     *                                  生产环境建议显式配置，防止 Host 头被改写时失效。
     * @param bool     $requireSource   完全取不到来源证据时是否拒绝（默认 false，
     *                                  交由包内 CsrfTokenMiddleware 兜底；
     *                                  置 true 才是「必须带来源」的严格模式）
     * @param bool     $rejectSameSite  `Sec-Fetch-Site: same-site` 是否也拒绝（默认 true）
     * @param bool     $trustFetchSite  `Sec-Fetch-Site: same-origin` 是否可作为来源证据
     *                                  （默认 true；关闭后退回只看 Origin/Referer）
     */
    public function __construct(
        protected array $allowedHosts = [],
        protected bool $requireSource = false,
        protected bool $rejectSameSite = true,
        protected bool $trustFetchSite = true
    ) {
        $this->allowedHosts = array_values(array_filter(array_map(
            fn($h) => $this->normalizeHost((string) $h),
            $this->allowedHosts
        )));
    }

    public function handle(LoginPayload $payload, Closure $next)
    {
        $decision = $this->evaluate($payload->request);

        if ($decision['status'] === 'skipped') {
            $payload->log(static::class, 'skipped', $decision['reason']);
            return $next($payload);
        }

        if ($decision['allowed']) {
            $payload->log(static::class, 'passed', $decision['reason']);
            return $next($payload);
        }

        $payload->log(static::class, 'blocked', $decision['reason']);
        $this->logBlocked($payload, $decision['reason']);

        return $this->error('请求来源不被允许', [], 403);
    }

    /**
     * 判定一次请求是否允许通过
     *
     * 与 handle() 拆开：拒绝分支要走 JsonResponse 渲染（依赖完整容器），
     * 判定逻辑独立后可在无容器环境下单测，也便于排障时复用。
     *
     * @return array{status:string, allowed:bool, reason:string}
     *         status: skipped | passed | blocked
     */
    public function evaluate($request): array
    {
        $method = strtoupper((string) $request->method());

        if (in_array($method, self::SAFE_METHODS, true)) {
            return $this->decision('skipped', true, '只读请求');
        }

        $fetchSite = strtolower(trim((string) $request->header('Sec-Fetch-Site', '')));
        if ($fetchSite === 'cross-site') {
            return $this->decision('blocked', false, 'Sec-Fetch-Site: cross-site');
        }
        if ($fetchSite === 'same-site' && $this->rejectSameSite) {
            return $this->decision('blocked', false, 'Sec-Fetch-Site: same-site（子域不可信）');
        }

        $originHeader = trim((string) $request->header('Origin', ''));
        $source = $this->extractHost($originHeader)
            ?? $this->extractHost((string) $request->header('Referer', ''));

        if ($source === null) {
            if ($originHeader !== '') {
                return $this->decision('blocked', false, 'Origin 为 opaque/null 来源');
            }

            if ($this->trustFetchSite && $fetchSite === 'same-origin') {
                return $this->decision('passed', true, 'Sec-Fetch-Site: same-origin（未携带 Origin/Referer）');
            }

            return $this->requireSource
                ? $this->decision('blocked', false, '缺少 Origin/Referer/Sec-Fetch-Site')
                : $this->decision('passed', true, '无来源证据，交由 CsrfTokenMiddleware 兜底');
        }

        $allowed = $this->allowedHostHosts($request);

        if (in_array($source, $allowed, true)) {
            return $this->decision('passed', true, '同源命中: ' . $source);
        }

        return $this->decision('blocked', false, '跨源拒绝: ' . $source);
    }

    /**
     * 允许的 host 集合：显式配置优先，未配置时回落到当前请求 Host
     *
     * @return string[]
     */
    protected function allowedHostHosts($request): array
    {
        if (!empty($this->allowedHosts)) {
            return $this->allowedHosts;
        }

        $host = $this->normalizeHost((string) $request->host());

        return $host !== '' ? [$host] : [];
    }

    /**
     * 从 Origin / Referer 中提取 host
     *
     * `Origin: null`（沙箱 iframe 的隐私来源）、`file://` 等取不到 host 的值
     * 一律返回 null，交由 require_source 分支处理（默认即拒绝）。
     */
    protected function extractHost(string $url): ?string
    {
        $url = trim($url);
        if ($url === '') {
            return null;
        }

        $parts = parse_url($url);
        if ($parts === false || empty($parts['host'])) {
            return null;
        }

        return $this->normalizeHost((string) $parts['host']);
    }

    /**
     * 归一化 host：小写、去首尾空白与结尾点
     *
     * 只比较 host 本身，不比较协议与端口：
     *   - 协议差异已由 `think\Request::isSsl()`（支持 X-Forwarded-Proto）处理，
     *     反向代理终止 TLS 不会造成误判，因此无需为此开白名单口子；
     *   - CSRF 的攻击面本质是「主机是否可信」，端口不构成安全边界。
     */
    protected function normalizeHost(string $host): string
    {
        $host = strtolower(trim($host));
        $host = rtrim($host, '.');

        if (str_starts_with($host, '[')) {
            $end = strpos($host, ']');
            if ($end !== false) {
                return substr($host, 0, $end + 1);
            }
            return $host;
        }

        $pos = strrpos($host, ':');
        if ($pos !== false && strpos($host, ':') === $pos) {
            return substr($host, 0, $pos);
        }

        return $host;
    }

    /**
     * 记录拦截日志（走上下文日志，便于与 request_id / 审计串联）
     */
    protected function logBlocked(LoginPayload $payload, string $reason): void
    {
        try {
            $request = $payload->request;

            ContextualLogger::warning('[same-origin] 登录来源校验未通过', [
                'reason'          => $reason,
                'path'            => (string) $request->pathinfo(),
                'ip'              => $payload->ip,
                'origin_host'     => $this->extractHost((string) $request->header('Origin', '')),
                'referer_host'    => $this->extractHost((string) $request->header('Referer', '')),
                'sec_fetch_site'  => (string) $request->header('Sec-Fetch-Site', ''),
                'sec_fetch_mode'  => (string) $request->header('Sec-Fetch-Mode', ''),
                'host'            => $this->normalizeHost((string) $request->host()),
            ]);
        } catch (\Throwable $e) {
        }
    }

    /**
     * @return array{status:string, allowed:bool, reason:string}
     */
    protected function decision(string $status, bool $allowed, string $reason): array
    {
        return [
            'status'  => $status,
            'allowed' => $allowed,
            'reason'  => $reason,
        ];
    }
}
