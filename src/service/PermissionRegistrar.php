<?php
/**
 * 权限注册与缓存管理服务
 *
 * 负责从多种来源（数据库/控制器 Attribute/配置）加载权限定义，
 * 同步到数据库，并管理权限缓存。
 */
namespace wise\auth\service;

use wise\auth\attribute\AuthPermission;
use wise\auth\model\Permission;
use wise\auth\service\RbacManager;
use wise\auth\traits\CacheKeyHelper;

class PermissionRegistrar
{
    use CacheKeyHelper;

    /**
     * 注册所有权限（从所有配置的来源加载并同步到数据库）
     *
     * @return int 注册的权限数量
     */
    public function register(): int
    {
        $sources = config('wise-auth.permission_sources', ['database']);
        $count = 0;

        foreach ($sources as $source) {
            switch ($source) {
                case 'config':
                    $count += $this->registerFromConfig();
                    break;
                case 'attribute':
                    $count += $this->registerFromAttributes();
                    break;
                case 'database':
                    // 数据库驱动无需额外注册，权限由管理员在后台管理
                    break;
                default:
                    $this->trace("未知的权限来源 [{$source}]，可选值：database / attribute / config");
                    break;
            }
        }

        // 清除权限缓存
        $this->clearPermissionsCache();

        return $count;
    }

    /**
     * 从配置文件注册权限
     *
     * @return int
     */
    protected function registerFromConfig(): int
    {
        $permissions = config('wise-auth.permissions', []);
        if (empty($permissions)) {
            return 0;
        }

        return Permission::loadFromConfig($permissions);
    }

    /**
     * 从控制器 Attribute（#[AuthPermission]）注册权限
     *
     * 扫描 attribute_dirs 下的 PHP 文件，读取类/方法上的 Permission Attribute，
     * 类级声明作为默认值，方法级声明生成权限节点。
     *
     * @return int
     */
    protected function registerFromAttributes(): int
    {
        $dirs = config('wise-auth.attribute_dirs', []);
        if (empty($dirs)) {
            return 0;
        }

        $count = 0;

        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            foreach ($this->scanPhpFiles($dir) as $file) {
                $permissions = $this->parseAttributePermissions($file);
                if (!empty($permissions)) {
                    $count += Permission::loadFromConfig($permissions);
                }
            }
        }

        return $count;
    }

    /**
     * 扫描目录下的PHP文件
     *
     * @param string $dir
     * @return array
     */
    protected function scanPhpFiles(string $dir): array
    {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * 解析单个文件中的 #[AuthPermission] 声明
     *
     * @param string $filePath
     * @return array<int, array<string, mixed>> 可直接交给 Permission::loadFromConfig() 的权限数组
     */
    protected function parseAttributePermissions(string $filePath): array
    {
        $class = $this->resolveClassName($filePath);
        if ($class === null) {
            return [];
        }

        // Attribute 必须通过反射读取，前提是类可加载。
        // 本链路面向宿主 app/ 控制器（composer PSR-4 自动加载，CLI 下同样可加载）；
        // 插件在 CLI 下不注册 plugin\* 命名空间，插件权限改由 manifest.json 的
        // menus（docblock @menu）/ permissions 声明，经 plugin:menu-migrate 与
        // menu:permission-sync 落库，不参与本扫描。
        // 因此 class_exists 失败只可能是类名写错或父类缺失；跳过单个文件即可，
        // 不阻断整轮权限同步。
        if (!$this->typeExists($class)) {
            $this->trace("类 {$class} 无法加载（{$filePath}），已跳过");

            return [];
        }

        try {
            $reflection = new \ReflectionClass($class);
        } catch (\Throwable $e) {
            $this->trace("反射 {$class} 失败：" . $e->getMessage());

            return [];
        }

        // 类级 Attribute 只贡献默认值，ident 不参与继承（否则每个方法都会生成同一条权限）
        $defaults = [];
        foreach ($reflection->getAttributes(AuthPermission::class) as $attribute) {
            $defaults = array_merge($defaults, $this->attributeToArray($attribute));
        }
        unset($defaults['ident']);

        $permissions = [];

        foreach ($reflection->getMethods() as $method) {
            foreach ($method->getAttributes(AuthPermission::class) as $attribute) {
                $permission = array_merge($defaults, $this->attributeToArray($attribute));

                if (!isset($permission['ident']) || $permission['ident'] === '') {
                    $this->trace("{$class}::{$method->getName()} 的 #[AuthPermission] 缺少 ident，已忽略");
                    continue;
                }

                $permissions[] = $permission;
            }
        }

        return $permissions;
    }

    /**
     * 从 PHP 源码中解析出「命名空间 + 类名」
     *
     * 只做 token 级解析，不加载类，避免扫描阶段触发 autoload 副作用。
     * 返回文件中的第一个具名类（接口/trait/enum 同样识别）。
     *
     * @param string $filePath
     * @return string|null 完整类名，解析失败返回 null
     */
    protected function resolveClassName(string $filePath): ?string
    {
        $code = @file_get_contents($filePath);
        if ($code === false || trim($code) === '') {
            return null;
        }

        $tokens = @token_get_all($code);
        $total  = count($tokens);
        $namespace = '';

        for ($i = 0; $i < $total; $i++) {
            $token = $tokens[$i];

            if (!is_array($token)) {
                continue;
            }

            if ($token[0] === T_NAMESPACE) {
                $namespace = $this->readNamespace($tokens, $i, $total);
                continue;
            }

            $isClassLike = in_array($token[0], [T_CLASS, T_INTERFACE, T_TRAIT, T_ENUM], true);
            if (!$isClassLike) {
                continue;
            }

            // 排除 `Foo::class` 与匿名类 `new class {...}`
            $prev = $this->neighborToken($tokens, $i, -1);
            if (is_array($prev) && in_array($prev[0], [T_DOUBLE_COLON, T_NEW], true)) {
                continue;
            }

            $next = $this->neighborToken($tokens, $i, 1);
            if (!is_array($next) || $next[0] !== T_STRING) {
                continue;
            }

            return $namespace === '' ? $next[1] : $namespace . '\\' . $next[1];
        }

        return null;
    }

    /**
     * 读取 T_NAMESPACE 之后的命名空间名
     *
     * @param array $tokens
     * @param int   $index T_NAMESPACE 所在下标
     * @param int   $total
     * @return string
     */
    protected function readNamespace(array $tokens, int $index, int $total): string
    {
        $namespace = '';
        $allowed   = [T_STRING, T_NS_SEPARATOR, T_NAME_QUALIFIED];

        for ($i = $index + 1; $i < $total; $i++) {
            $token = $tokens[$i];

            if (is_array($token) && in_array($token[0], $allowed, true)) {
                $namespace .= $token[1];
                continue;
            }

            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            break;
        }

        return $namespace;
    }

    /**
     * 获取指定下标前后最近的有效 token（跳过空白与注释）
     *
     * @param array $tokens
     * @param int   $index
     * @param int   $step  -1 向前，1 向后
     * @return array|string|null
     */
    protected function neighborToken(array $tokens, int $index, int $step)
    {
        $total = count($tokens);

        for ($i = $index + $step; $i >= 0 && $i < $total; $i += $step) {
            $token = $tokens[$i];

            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            return $token;
        }

        return null;
    }

    /**
     * 判断类/接口/trait/enum 是否可加载
     *
     * class_exists() 对 interface / trait 恒返回 false（即使 autoload 成功），
     * 故按类型分别探测，与 resolveClassName() 的识别范围保持一致。
     *
     * @param string $name
     * @return bool
     */
    protected function typeExists(string $name): bool
    {
        return class_exists($name)
            || interface_exists($name)
            || trait_exists($name)
            || enum_exists($name);
    }

    /**
     * 实例化 Attribute 并转为数组
     *
     * @param \ReflectionAttribute $attribute
     * @return array<string, mixed>
     */
    protected function attributeToArray(\ReflectionAttribute $attribute): array
    {
        try {
            $instance = $attribute->newInstance();
        } catch (\Throwable $e) {
            $this->trace('#[AuthPermission] 实例化失败：' . $e->getMessage());

            return [];
        }

        return $instance instanceof AuthPermission ? $instance->toArray() : [];
    }

    /**
     * 记录扫描过程的非致命问题（仅 debug 下可见，不影响注册流程）
     *
     * @param string $message
     * @return void
     */
    protected function trace(string $message): void
    {
        if (function_exists('trace')) {
            trace('[wise-auth] ' . $message, 'warning');
        }
    }

    /**
     * 获取所有已注册权限
     *
     * @param bool $tree 是否返回树结构
     * @return array
     */
    public function getAllPermissions(bool $tree = false): array
    {
        if ($tree) {
            return app(RbacManager::class)->buildTree(
                Permission::where('status', 1)->order('sort', 'asc')->select()->toArray()
            );
        }

        return Permission::where('status', 1)->order('sort', 'asc')->select()->toArray();
    }

    /**
     * 获取权限映射表（ident => permission数据）
     *
     * @return array
     */
    public function getPermissionMap(): array
    {
        $this->initCache();
        $cacheKey = $this->getCacheKey('permission_map');

        // 如果缓存可用，先尝试从缓存读取
        if ($this->cacheEnabled && $this->cache) {
            $cached = $this->cache->get($cacheKey);
            if ($cached !== null) {
                return $cached;
            }
        }

        // 直接从数据库查询
        $map = [];
        $permissions = Permission::where('status', 1)->select()->toArray();
        foreach ($permissions as $perm) {
            $map[$perm['ident']] = $perm;
        }

        // 写入缓存（如果可用）
        if ($this->cacheEnabled && $this->cache) {
            $this->cache->set($cacheKey, $map, 3600);
        }

        return $map;
    }

    /**
     * 清除权限缓存
     */
    public function clearPermissionsCache(): void
    {
        $this->initCache();

        // 删除单键缓存
        if ($this->cacheEnabled && $this->cache) {
            $this->cache->delete($this->getCacheKey('permission_map'));
            $this->cache->delete($this->getCacheKey('route_perms_map'));
        }

        // 尝试 tag 清除（best-effort；必须作用于包专属 store，而非框架默认 store）
        if ($this->cacheEnabled && $this->cache) {
            try {
                $this->cache->tag('wiseauth_permissions')->clear();
            } catch (\Throwable) {
                // Tag 驱动不支持时静默忽略
            }
        }

        // 单路由匹配结果缓存（route_match:*）同样必须失效，否则「改了权限 route 却不生效」。
        // 该键按路由动态生成、无法穷举，统一委托 RbacManager 以「代际递增」整体失效。
        try {
            app(RbacManager::class)->clearRouteMatchCache();
        } catch (\Throwable) {
            // 包未完全启动等异常场景静默忽略（缓存会随 TTL 自然过期）
        }
    }

    /**
     * 检查权限标识是否存在
     *
     * @param string $ident
     * @return bool
     */
    public function hasPermission(string $ident): bool
    {
        $map = $this->getPermissionMap();
        return isset($map[$ident]);
    }
}
