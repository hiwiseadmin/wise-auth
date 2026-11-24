<?php
/**
 * PHPUnit 测试引导文件
 *
 * 通过 ThinkPHP Stub 类提供单元测试隔离环境，
 * 使 wise-auth 单元测试可在不启动完整 ThinkPHP 应用的情况下运行。
 */

error_reporting(E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED);

if (!defined('DS')) {
    define('DS', DIRECTORY_SEPARATOR);
}
if (!defined('ROOT_PATH')) {
    define('ROOT_PATH', dirname(__DIR__, 4) . DS);
}
if (!defined('APP_PATH')) {
    define('APP_PATH', ROOT_PATH . 'app' . DS);
}
if (!defined('RUNTIME_PATH')) {
    define('RUNTIME_PATH', ROOT_PATH . 'runtime' . DS);
}

require_once __DIR__ . '/stubs/think_stubs.php';

$vendorDir = dirname(__DIR__, 4) . '/vendor';
$manualMap = [
    'wise\\auth\\'      => [
        dirname(__DIR__) . '/src/',
        dirname(__DIR__) . '/src/facade/',
    ],
    'wise\\auth\\tests\\' => [__DIR__ . '/'],
    'Mockery\\'          => [$vendorDir . '/mockery/mockery/Mockery/'],
];

if (file_exists($vendorDir . '/mockery/mockery/Mockery.php')) {
    require_once $vendorDir . '/mockery/mockery/Mockery.php';
}
if (file_exists($vendorDir . '/mockery/mockery/helpers.php')) {
    require_once $vendorDir . '/mockery/mockery/helpers.php';
}

spl_autoload_register(function ($class) use ($manualMap) {
    foreach ($manualMap as $prefix => $dirs) {
        $len = strlen($prefix);
        if (strncmp($prefix, $class, $len) === 0) {
            $relativeClass = substr($class, $len);
            $file = str_replace('\\', '/', $relativeClass) . '.php';
            foreach ($dirs as $dir) {
                $fullPath = $dir . $file;
                if (file_exists($fullPath)) {
                    require_once $fullPath;
                    return;
                }
            }
        }
    }
});

if (!function_exists('app')) {
    function app($abstract = null)
    {
        static $instances = [];
        if ($abstract === null) {
            return new class($instances) {
                private $instances;
                public function __construct(&$instances) { $this->instances = &$instances; }
                public function make($class) { return $this->instances[$class] ?? null; }
                public function bind($abstract, $concrete) { $this->instances[$abstract] = $concrete; }
            };
        }
        if ($abstract === 'http') {
            return new class {
                public function getName() { return 'admin'; }
            };
        }
        return $instances[$abstract] ?? null;
    }
}

if (!class_exists(\WiseAuthTestResponse::class)) {
    class WiseAuthTestResponse extends \think\response\Json
    {
        private $testData;
        private $testCode;
        private $testRedirectUrl = null;

        public function __construct($data = null, $code = 200)
        {
            $this->testData = $data;
            $this->testCode = $code;
        }

        public function code($code = null)
        {
            if ($code === null) {
                return $this->testCode;
            }
            $this->testCode = $code;
            return $this;
        }

        public function getData() { return $this->testData; }
        /**
         * 输出内容
         *
         * 与 \think\Response::getContent() 口径一致：数组/对象按 JSON 输出。
         * 此前只处理字符串，导致「JSON 响应体是否包含某文案」这类断言恒为 ''，
         * 用例红在断言而非被测代码上（IpGuard 两条即属此类）。
         */
        public function getContent(): string
        {
            if (is_string($this->testData)) {
                return $this->testData;
            }
            if ($this->testData === null) {
                return '';
            }
            if (is_array($this->testData) || is_object($this->testData)) {
                return (string) json_encode($this->testData, JSON_UNESCAPED_UNICODE);
            }

            return (string) $this->testData;
        }

        public function redirect($url)
        {
            $this->testRedirectUrl = $url;
            $this->testCode = 302;
            return $this;
        }

        public function getTargetUrl() { return $this->testRedirectUrl; }
    }
}

if (!function_exists('config')) {
    function config($key = null, $default = null)
    {
        static $config = [];
        if ($key === null) {
            return $config;
        }
        if (isset($GLOBALS['_test_config'])) {
            $keys = explode('.', $key);
            $value = $GLOBALS['_test_config'];
            foreach ($keys as $k) {
                if (!is_array($value) || !array_key_exists($k, $value)) {
                    if ($k === 'wise-auth' && array_key_exists('wiseauth', $value)) {
                        $value = $value['wiseauth'];
                        continue;
                    }
                    if ($k === 'wiseauth' && array_key_exists('wise-auth', $value)) {
                        $value = $value['wise-auth'];
                        continue;
                    }
                    return $default;
                }
                $value = $value[$k];
            }
            return $value;
        }
        $keys = explode('.', $key);
        $value = $config;
        foreach ($keys as $k) {
            if (!is_array($value) || !array_key_exists($k, $value)) {
                return $default;
            }
            $value = $value[$k];
        }
        return $value;
    }
}

if (!function_exists('session')) {
    function session($name = null, $default = null)
    {
        static $data = [];
        if ($name === null) {
            return $data;
        }
        return $data[$name] ?? $default;
    }
}

if (!function_exists('json')) {
    function json($data = [], $code = 200)
    {
        return new \WiseAuthTestResponse($data, $code);
    }
}

if (!function_exists('redirect')) {
    function redirect($url, $params = [], $code = 302)
    {
        return (new \WiseAuthTestResponse(null, $code))->redirect($url);
    }
}

if (!function_exists('view')) {
    function view($message = '')
    {
        return new \WiseAuthTestResponse($message, 500);
    }
}

if (!function_exists('event')) {
    function event($name, $params = null)
    {
        static $events = [];
        if ($params === null && $name === null) {
            return $events;
        }
        $events[] = ['name' => $name, 'params' => $params];
    }
}

if (!function_exists('env')) {
    function env(string $name, mixed $default = null): mixed
    {
        $value = getenv($name);

        return $value === false ? $default : $value;
    }
}

$configFile = __DIR__ . '/../config/wise-auth.php';
if (file_exists($configFile)) {
    $wiseauthConfig = require $configFile;
    $GLOBALS['_test_config']['wise-auth'] = $wiseauthConfig;
}

$GLOBALS['_test_config']['wise-auth']['login']['events']['log_to_database'] = false;
$GLOBALS['_test_config']['wise-auth']['login']['events']['log_to_file']     = false;

$GLOBALS['_bootstrap_test_config'] = $GLOBALS['_test_config'];


require_once __DIR__ . '/stubs/test_doubles.php';

/**
 * 装配（或重建）测试容器
 *
 * 注意 `think\Container::getInstance()` 是**进程级单例**：任何用例只要执行了
 * `new \think\App()`（例如 ContractTest 为构造 ServiceProvider 而新建 App），
 * 全局实例就会被换成一个空容器，此前绑定的缓存与锁管理器全部丢失。
 * 因此这里做成「按需重建」，并由 `wise_auth_test_app()` 统一入口保证幂等。
 */
function wise_auth_test_build_container(): \think\App
{
    $app      = new \think\App(ROOT_PATH);
    $cache    = new WiseAuthTestCache();
    $attempts = new WiseAuthTestFailedAttemptStore();

    $app->instance('cache', $cache);
    $app->instance(\think\Cache::class, $cache);

    $app->instance(\think\App::class, $app);

    $app->instance('event', new \think\Event($app));

    $attemptsConfig = (array) ($GLOBALS['_test_config']['wise-auth']['login']['failed_attempts'] ?? []);
    $app->instance(\wise\login\lock\FailedAttemptStoreInterface::class, $attempts);
    $app->instance(
        \wise\login\lock\LoginLockManager::class,
        new \wise\login\lock\LoginLockManager($app, $attempts, $attemptsConfig)
    );

    return $app;
}

/**
 * 取得可用的测试容器；全局实例被用例替换掉时自动重建。
 */
function wise_auth_test_app(): \think\App
{
    $current = \think\Container::getInstance();

    if ($current instanceof \think\App && $current->exists(\think\Cache::class)) {
        return $current;
    }

    return wise_auth_test_build_container();
}

/**
 * 用例级复位：恢复基线配置 + 清空缓存与失败计数器
 *
 * 用途：`wise\login` 下直接继承 PHPUnit TestCase 的用例（不经过 tests/TestCase.php），
 * 会继承「上一个用例类」留下的全局配置与缓存状态（例如备份码限流的失败计数、
 * 登录锁定的失败次数），导致顺序相关的假失败。在 setUp 里调用一次即可。
 */
function wise_auth_test_reset(): void
{
    $GLOBALS['_test_config'] = $GLOBALS['_bootstrap_test_config'] ?? [];

    $app = wise_auth_test_app();

    $cache = $app->make(\think\Cache::class);
    if (method_exists($cache, 'clear')) {
        $cache->clear();
    }

    $store = $app->make(\wise\login\lock\FailedAttemptStoreInterface::class);
    if (method_exists($store, 'flush')) {
        $store->flush();
    }
}

wise_auth_test_app();
