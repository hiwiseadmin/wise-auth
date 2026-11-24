<?php
declare(strict_types=1);

use think\migration\Migrator;
use think\migration\db\Column;

/**
 * TOTP 配置表（多态关联）
 *
 * 通过 user_type + user_id 联合键支持多种用户类型（admin / member / ...）
 * 包内自建，不修改任何用户原表。
 */
class CreateTotpConfigTable extends Migrator
{
    protected function getTable(): string
    {
        return 'auth_totp_configs';
    }

    public function up(): void
    {
        $table = $this->table($this->getTable(), [
            'engine'    => 'InnoDB',
            'comment'   => 'TOTP 配置表（多态关联）',
            'collation' => 'utf8mb4_unicode_ci',
        ]);

        $table->addColumn(Column::string('user_type', 50)->setDefault('admin')->setNull(false)->setComment('多态类型：admin / member 等'))
              ->addColumn(Column::integer('user_id')->setNull(false)->setComment('用户 ID'))
              ->addColumn(Column::string('totp_secret', 64)->setNull(true)->setComment('TOTP 密钥（Base32）'))
              ->addColumn(Column::text('totp_backup_codes')->setNull(true)->setComment('备份码（JSON 哈希集合）'))
              ->addColumn(Column::integer('totp_enabled')->setLimit(1)->setDefault(0)->setNull(false)->setComment('是否启用 TOTP'))
              ->addColumn(Column::text('totp_recovery_codes')->setNull(true)->setComment('恢复码 JSON 哈希集合（P2-#17）'))
              ->addColumn(Column::dateTime('create_time')->setNull(false)->setComment('创建时间'))
              ->addColumn(Column::dateTime('update_time')->setNull(false)->setComment('更新时间'))
              ->addColumn(Column::dateTime('delete_time')->setNull(true)->setComment('软删除时间（NULL=未删除）'))
              ->addIndex(['user_type', 'user_id'], ['unique' => true])
              ->create();
    }

    public function down(): void
    {
        $tableName = $this->getTable();

        if ($this->hasTable($tableName)) {
            $this->table($tableName)->drop()->save();
        }
    }
}
