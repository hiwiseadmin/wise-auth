<?php
/**
 * PHPUnit 测试引导文件
 *
 * 通过 ThinkPHP Stub 类提供单元测试隔离环境，
 * 使 wise-auth 单元测试可在不启动完整 ThinkPHP 应用的情况下运行。
 */

// 禁用已弃用警告（PHP 8.x 兼容）
error_reporting(E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED);

// 定义 ThinkPHP 常量
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

// 加载 ThinkPHP Stub 类（单元测试隔离环境）
require_once __DIR__ . '/stubs/think_stubs.php';

// 手动注册 PSR-4 自动加载
$vendorDir = dirname(__DIR__, 4) . '/vendor';
$manualMap = [
    'wise\\auth\\'      => [
        dirname(__DIR__) . '/src/',
        dirname(__DIR__) . '/src/facade/',  // Rbac facade 使用 wise\auth 命名空间但在 facade/ 子目录
    ],
    'wise\\auth\\tests\\' => [__DIR__ . '/'],
    'Mockery\\'          => [$vendorDir . '/mockery/mockery/Mockery/'],
];

// 加载 Mockery 文件级自动加载
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

// ThinkPHP polyfill 函数
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
        // app('http') → 模拟多应用名
        if ($abstract === 'http') {
            return new class {
                public function getName() { return 'admin'; }
            };
        }
        return $instances[$abstract] ?? null;
    }
}

// 测试专用 Response 类
// 继承 \think\response\Json 以兼容 wise-api 等包中 Json 类型声明的返回类型检查
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
        public function getContent(): string { return is_string($this->testData) ? $this->testData : ''; }

        public function redirect($url)
        {
            $this->testRedirectUrl = $url;
            $this->testCode = 302;
            return $this;
        }

        public function getTargetUrl() { return $this->testRedirectUrl; }
        // header() 直接继承父类 \think\Response，无需覆盖
    }
}

if (!function_exists('config')) {
    function config($key = null, $default = null)
    {
        static $config = [];
        if ($key === null) {
            return $config;
        }
        // 优先从测试用例的 _test_config 读取
        if (isset($GLOBALS['_test_config'])) {
            $keys = explode('.', $key);
            $value = $GLOBALS['_test_config'];
            foreach ($keys as $k) {
                if (!is_array($value) || !array_key_exists($k, $value)) {
                    // 兼容测试配置键名变体（wiseauth ↔ wise-auth）
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

// 加载 wise-auth 默认配置
$configFile = __DIR__ . '/../config/wise-auth.php';
if (file_exists($configFile)) {
    $wiseauthConfig = require $configFile;
    $GLOBALS['_test_config']['wise-auth'] = $wiseauthConfig;
}
