<?php
/**
 * ThinkPHP 框架 Stub 类（用于单元测试隔离）
 *
 * 当 Composer 已安装真实 ThinkPHP 框架时，跳过重复声明。
 */

namespace think;

// =============================
// Container & App
// =============================

if (!class_exists(Container::class)) {
class Container
{
    protected static $instance;
    protected $instances = [];

    public static function getInstance()
    {
        if (!static::$instance) {
            static::$instance = new static();
        }
        return static::$instance;
    }

    public function make($abstract)
    {
        return $this->instances[$abstract] ?? null;
    }

    public function bind($abstract, $concrete)
    {
        $this->instances[$abstract] = $concrete;
    }
}
}

if (!class_exists(App::class)) {
class App extends Container {}
}

// =============================
// Model
// =============================

if (!class_exists(Model::class)) {
class Model implements \ArrayAccess, \JsonSerializable
{
    protected $name = '';
    protected $autoWriteTimestamp = false;
    protected $createTime = 'create_time';
    protected $updateTime = 'update_time';
    protected $deleteTime = 'delete_time';
    protected $type = [];
    protected $json = [];
    protected $readonly = [];
    protected $data = [];

    public function __construct($data = [])
    {
        $this->data = $data;
    }

    public function getKey()
    {
        return $this->data['id'] ?? null;
    }

    public function save($data = [], $where = [], $sequence = null)
    {
        return true;
    }

    public static function create($data = [], $field = [], $replace = false)
    {
        return new static($data);
    }

    public static function find($id)
    {
        return null;
    }

    // ============ Query Builder Stub ============
    protected static $queryResults = [];
    protected $queryConditions = [];

    public static function setQueryResults(array $results): void
    {
        static::$queryResults[static::class] = $results;
    }

    public static function where($field, $op = null, $value = null): self
    {
        $instance = new static();
        $instance->queryConditions['where'][] = [$field, $op, $value];
        return $instance;
    }

    public static function whereIn($field, $values): self
    {
        $instance = new static();
        $instance->queryConditions['whereIn'][] = [$field, $values];
        return $instance;
    }

    public function column($field)
    {
        return array_column(static::$queryResults[static::class] ?? [], $field);
    }

    public function value($field)
    {
        $results = static::$queryResults[static::class] ?? [];
        $first = reset($results);
        return $first ? ($first[$field] ?? null) : null;
    }

    public function select()
    {
        return new \think\model\Collection(static::$queryResults[static::class] ?? []);
    }

    public function toArray()
    {
        return static::$queryResults[static::class] ?? [];
    }

    public function order($field, $direction = 'asc')
    {
        return $this;
    }

    public function __get($name)
    {
        return $this->data[$name] ?? null;
    }

    public function __set($name, $value)
    {
        $this->data[$name] = $value;
    }

    #[\ReturnTypeWillChange]
    public function offsetExists($offset): bool
    {
        return isset($this->data[$offset]);
    }

    #[\ReturnTypeWillChange]
    public function offsetGet($offset)
    {
        return $this->data[$offset];
    }

    #[\ReturnTypeWillChange]
    public function offsetSet($offset, $value): void
    {
        $this->data[$offset] = $value;
    }

    #[\ReturnTypeWillChange]
    public function offsetUnset($offset): void
    {
        unset($this->data[$offset]);
    }

    #[\ReturnTypeWillChange]
    public function jsonSerialize()
    {
        return $this->data;
    }
}
}

// =============================
// Facade
// =============================

if (!class_exists(Facade::class)) {
class Facade
{
    protected static $instance = [];

    protected static function getFacadeClass(): string
    {
        return '';
    }

    public static function __callStatic($method, $args)
    {
        $class = static::getFacadeClass();
        if (!isset(static::$instance[$class])) {
            static::$instance[$class] = new $class();
        }
        return call_user_func_array([static::$instance[$class], $method], $args);
    }
}
}

// =============================
// Exception
// =============================

if (!class_exists(Exception::class)) {
class Exception extends \Exception {}
}

// =============================
// Service
// =============================

if (!class_exists(Service::class)) {
class Service
{
    protected $app;

    public function __construct(App $app)
    {
        $this->app = $app;
    }

    public function register() {}
    public function boot() {}
}
}

// =============================
// Request & Response
// =============================

if (!class_exists(Request::class)) {
class Request
{
    public function baseUrl()
    {
        return '/';
    }

    public function method()
    {
        return 'GET';
    }

    public function isAjax()
    {
        return false;
    }

    public function isJson()
    {
        return false;
    }

    public function controller()
    {
        return 'index';
    }

    public function action()
    {
        return 'index';
    }

    public function __get($name)
    {
        return null;
    }
}
}

if (!class_exists(Response::class)) {
class Response
{
    protected $data;
    protected $code = 200;
    protected $headers = [];
    protected $redirectUrl = null;

    public function __construct($data = null, $code = 200)
    {
        $this->data = $data;
        $this->code = $code;
    }

    public static function create($data = null, $code = 200)
    {
        return new static($data, $code);
    }

    public function code($code = null)
    {
        if ($code === null) {
            return $this->code;
        }
        $this->code = $code;
        return $this;
    }

    public function getData()
    {
        return $this->data;
    }

    public function getContent()
    {
        return $this->data;
    }

    public function redirect($url)
    {
        $this->redirectUrl = $url;
        $this->code = 302;
        return $this;
    }

    public function getTargetUrl()
    {
        return $this->redirectUrl;
    }

    public function header($key, $value)
    {
        $this->headers[$key] = $value;
        return $this;
    }
}
}

namespace think\console;

if (!class_exists(Command::class)) {
class Command
{
    protected function setName(string $name): static { return $this; }
    protected function setDescription(string $description): static { return $this; }
    protected function addArgument(string $name, int $mode = 1, string $description = '', $default = null): static { return $this; }
    protected function addOption(string $name, $shortcut = null, int $mode = 1, string $description = '', $default = null): static { return $this; }
    protected function setHelp(string $help): static { return $this; }
    protected function configure() {}
    protected function execute($input, $output) {}
}
}

if (!class_exists(Input::class)) {
class Input {}
}

if (!class_exists(Output::class)) {
class Output {}
}

namespace think\facade;

if (!class_exists(Cache::class)) {
class Cache
{
    protected static $store = null;

    public static function store($name = null)
    {
        if (static::$store === null) {
            static::$store = new class {
                private $data = [];

                public function get($key) { return $this->data[$key] ?? null; }
                public function set($key, $value, $ttl = null) { $this->data[$key] = $value; return true; }
                public function delete($key) { unset($this->data[$key]); return true; }
                public function handler() { return $this; }
                public function keys($pattern)
                {
                    $pattern = '#^' . str_replace('*', '.*', $pattern) . '$#';
                    $matched = [];
                    foreach (array_keys($this->data) as $key) {
                        if (preg_match($pattern, $key)) {
                            $matched[] = $key;
                        }
                    }
                    return $matched;
                }
                public function del($keys)
                {
                    foreach ((array)$keys as $key) { unset($this->data[$key]); }
                    return true;
                }
            };
        }
        return static::$store;
    }

    public static function tag($tag) { return static::store(); }
    public static function __callStatic($method, $args)
    {
        return call_user_func_array([static::store(), $method], $args);
    }
}
}

if (!class_exists(Db::class)) {
class Db
{
    public static function name($table)
    {
        return new class($table) {
            private $table;
            private $wheres = [];

            public function __construct($table) { $this->table = $table; }

            public function where($field, $op = null, $value = null)
            {
                if ($op instanceof \Closure) { $op($this); }
                else { $this->wheres[] = [$field, $op ?? '=', $value]; }
                return $this;
            }

            public function whereIn($field, $values) { $this->wheres[] = ['in', $field, $values]; return $this; }
            public function whereNull($field) { $this->wheres[] = ['null', $field]; return $this; }
            public function whereOr($field, $op, $value) { $this->wheres[] = ['or', $field, $op, $value]; return $this; }
            public function column($field) { return []; }
            public function value($field) { return null; }
            public function select() { return []; }
            public function find() { return null; }
            public function count() { return 0; }
            public function toArray() { return []; }
            public function order($field, $direction = 'asc') { return $this; }
        };
    }
}
}

if (!class_exists(Event::class)) {
class Event
{
    protected static $listeners = [];

    public static function listen($event, $handler)
    {
        static::$listeners[$event][] = $handler;
    }

    public static function trigger($event, $params = [])
    {
        if (isset(static::$listeners[$event])) {
            foreach (static::$listeners[$event] as $handler) {
                call_user_func($handler, $params);
            }
        }
    }
}
}

namespace think\model;

if (!class_exists(Collection::class)) {
class Collection implements \ArrayAccess, \Countable, \IteratorAggregate
{
    protected $items = [];

    public function __construct($items = []) { $this->items = $items; }
    public function column($field) { return array_column($this->items, $field); }
    #[\ReturnTypeWillChange] public function offsetExists($offset): bool { return isset($this->items[$offset]); }
    #[\ReturnTypeWillChange] public function offsetGet($offset) { return $this->items[$offset]; }
    #[\ReturnTypeWillChange] public function offsetSet($offset, $value): void { $this->items[$offset] = $value; }
    #[\ReturnTypeWillChange] public function offsetUnset($offset): void { unset($this->items[$offset]); }
    #[\ReturnTypeWillChange] public function count(): int { return count($this->items); }
    #[\ReturnTypeWillChange] public function getIterator(): \Traversable { return new \ArrayIterator($this->items); }
    public function select() { return $this; }
}
}

namespace think\model\concern;

if (!trait_exists(SoftDelete::class)) {
trait SoftDelete {}
}

namespace think\model\relation;

if (!class_exists(BelongsTo::class)) {
class BelongsTo {}
}

if (!class_exists(HasMany::class)) {
class HasMany {}
}

if (!class_exists(BelongsToMany::class)) {
class BelongsToMany {}
}

if (!class_exists(MorphToMany::class)) {
class MorphToMany {}
}
