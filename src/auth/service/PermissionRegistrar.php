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
                    break;
                default:
                    $this->trace("未知的权限来源 [{$source}]，可选值：database / attribute / config");
                    break;
            }
        }

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
        try {
            return class_exists($name)
                || interface_exists($name)
                || trait_exists($name)
                || enum_exists($name);
        } catch (\Throwable) {
            return false;
        }
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

        if ($this->cacheEnabled && $this->cache) {
            $cached = $this->cacheGet($cacheKey);
            if ($cached !== null) {
                return $cached;
            }
        }

        $map = [];
        $permissions = Permission::where('status', 1)->select()->toArray();
        foreach ($permissions as $perm) {
            $map[$perm['ident']] = $perm;
        }

        if ($this->cacheEnabled && $this->cache) {
            $this->cacheSet($cacheKey, $map, 3600);
        }

        return $map;
    }

    /**
     * 清除权限缓存
     */
    public function clearPermissionsCache(): void
    {
        $this->initCache();

        if ($this->cacheEnabled && $this->cache) {
            $this->cacheDelete($this->getCacheKey('permission_map'));
            $this->cacheDelete($this->getCacheKey('route_perms_map'));
        }

        if ($this->cacheEnabled && $this->cache) {
            try {
                $this->cache->tag('wiseauth_permissions')->clear();
            } catch (\Throwable) {
            }
        }

        try {
            app(RbacManager::class)->clearRouteMatchCache();
        } catch (\Throwable) {
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
