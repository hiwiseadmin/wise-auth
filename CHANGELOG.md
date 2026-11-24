# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [1.0.2] - 2026-11-24

### 修复
- **缓存写失败不再拖垮业务**：`PermissionRegistrar` / `RbacManager` 的缓存读写改为经
  `CacheKeyHelper::cacheGet/cacheSet/cacheDelete/cacheInc` 包装（失败降级 + 一次重试 +
  每进程每键一次告警）。此前 File 驱动在 Windows 上遇到文件占用/只读时
  `file_put_contents(..., LOCK_EX)` 抛 `ErrorException`，会把整包菜单同步打断
  （`wise-agent: 同步失败 - ... Permission denied`，菜单一条都没落库）。
  缓存只是加速层，数据库是事实来源，失败只记 `[wise-auth][cache-degraded]` 日志。
- **无完整 App 时超管判定不再 500**：`RbacManager::loadSuperAdminIds()` 在拿不到
  `app()->getConfigPath()`（单元测试 stub / 极简 CLI 引导）时回落 `config()`，
  不再 `Call to a member function getConfigPath() on ...`；新增
  `resetSuperAdminIdsCache()` 供测试清理进程内静态缓存。

### 测试
- **测试套件修复（此前 18 errors / 9 failures，且 `TestUser` 签名不兼容导致进程 fatal）**：
  - `tests/stubs/TestUser` 与 `UserContract` 对齐（`getAuthIdentifier(): int|string`、
    `refreshPermissions()`、`forgetPermissions()`、`assignRole/syncRoles` 的 `$expiredAt`）；
  - `ContractTest` / `FacadeTest` 对齐真实类名与命名空间（`AuthServiceProvider`、
    `wise\auth\facade\Rbac`）；
  - `CacheKeyHelperTest` 去掉「缓存键拼表前缀」的不存在断言；
  - `RbacManagerTest` 的约束用例改测 `ConstraintEngine`（`checkBuiltinConstraints` /
    `checkMutualExclusion` 已迁出 RbacManager），超管用例关闭 `super_role` 分支以脱离数据库；
  - `ModelTest` 用 `tests/fixtures/AncestorTestRole`（内存 `find()`）替代无效的
    Mockery 静态 mock，并补 path 解析 / 父链回溯 / 环检测三个用例；
  - `RbacMiddlewareTest` 的路由用例改为三种真实形态（多应用 root、控制器名同应用名、
    自定义入口），后者是 `/admin/admin/getList` 回归守卫；
  - `phpunit.xml.dist` 迁移到 10.5 schema，消除弃用提示。
  现为 `228 tests / 487 assertions` 全绿。

## [1.0.0] - 2024-01-01

### Added
- Initial release

[1.0.0]: https://github.com/hiwiseadmin/wise-auth/releases/tag/v1.0.0

[Unreleased]: https://github.com/hiwiseadmin/wise-auth/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/hiwiseadmin/wise-auth/releases/tag/v1.0.2
