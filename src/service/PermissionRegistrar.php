<?php
/**
 * 权限注册与缓存管理服务
 *
 * 负责从多种来源（数据库/注解/配置）加载权限定义，
 * 同步到数据库，并管理权限缓存。
 */
namespace wise\auth\service;

use think\facade\Cache;
use wise\auth\model\Permission;
use wise\auth\service\RbacManager;
use wise\auth\trait\CacheKeyHelper;

class PermissionRegistrar
{
    use CacheKeyHelper;

    /**
     * 缓存实例
     *
     * @var \think\Cache
     */
    protected $cache;

    /**
     * 是否已初始化缓存驱动
     *
     * @var bool
     */
    protected $cacheInitialized = false;

    /**
     * 缓存是否已启用
     *
     * @var bool|null
     */
    protected $cacheEnabled = null;

    /**
     * 初始化缓存
     */
    protected function initCache(): void
    {
        if ($this->cacheInitialized) {
            return;
        }

        $this->cacheEnabled = config('wise-auth.cache_enabled', true);
        if ($this->cacheEnabled) {
            $store = config('wise-auth.cache_store');
            if ($store) {
                $this->cache = Cache::store($store);
            } else {
                $this->cache = Cache::store();
            }
        }

        $this->cacheInitialized = true;
    }

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
                case 'annotation':
                    $count += $this->registerFromAnnotations();
                    break;
                case 'database':
                    // 数据库驱动无需额外注册，权限由管理员在后台管理
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
     * 从控制器注解注册权限
     *
     * @return int
     */
    protected function registerFromAnnotations(): int
    {
        $dirs = config('wise-auth.annotation_dirs', []);
        if (empty($dirs)) {
            return 0;
        }

        $tag = config('wise-auth.annotation_tag', '@permission');
        $count = 0;

        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            $files = $this->scanPhpFiles($dir);
            foreach ($files as $file) {
                $permissions = $this->parseAnnotationPermissions($file, $tag);
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
     * 解析控制器文件中的权限注解
     *
     * 注解格式示例：
     *   /**
     *    * @permission ident="admin.user.list", name="管理员列表", type="route", route="/admin/admins/index"
     *    *\/
     *
     * @param string $filePath
     * @param string $tag
     * @return array
     */
    protected function parseAnnotationPermissions(string $filePath, string $tag): array
    {
        $content = file_get_contents($filePath);
        if ($content === false) {
            return [];
        }

        $permissions = [];
        $pattern = '/@' . preg_quote($tag, '/') . '\s+(.+)$/m';

        if (preg_match_all($pattern, $content, $matches)) {
            foreach ($matches[1] as $match) {
                $parsed = $this->parseAnnotationParams($match);
                if (!empty($parsed['ident'])) {
                    $permissions[] = $parsed;
                }
            }
        }

        return $permissions;
    }

    /**
     * 解析注解参数
     *
     * @param string $str 如: ident="admin.user.list", name="管理员列表"
     * @return array
     */
    protected function parseAnnotationParams(string $str): array
    {
        $result = [];
        $pattern = '/(\w+)\s*=\s*"([^"]*)"|(\w+)\s*=\s*\'([^\']*)\'/';

        if (preg_match_all($pattern, $str, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $key = $m[1] ?: $m[3];
                $value = $m[2] ?: $m[4];
                $result[$key] = $value;
            }
        }

        return $result;
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
        $cacheKey = $this->getCacheKey('permission_map');

        // 删除单键缓存
        if ($this->cacheEnabled && $this->cache) {
            $this->cache->delete($cacheKey);
        }

        // 尝试 tag 清除
        try {
            Cache::tag('wiseauth_permissions')->clear();
        } catch (\Exception $e) {
            // ignore
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
