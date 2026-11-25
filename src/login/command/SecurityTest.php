<?php
declare(strict_types=1);

namespace wise\login\command;

use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;
use wise\login\contract\TotpUserInterface;
use wise\login\ip\CidrMatcher;
use wise\login\totp\Base32;
use wise\login\totp\TotpManager;

/**
 * 自检命令：验证包的核心功能（IP 匹配、TOTP 码生成与校验、Base32 编解码等）
 *
 * 用法：
 *   php think wise:login:test
 *   php think wise:login:test --ip=192.168.1.100 --cidr=192.168.0.0/16
 *   php think wise:login:test --totp=JBSWY3DPEHPK3PXP --code=123456
 */
class SecurityTest extends Command
{
    protected function configure()
    {
        $this->setName('wise:login:test')
            ->setDescription('运行登录安全模块自检测试');

        $this->addOption('ip', null, Option::VALUE_OPTIONAL, '用于 CIDR 匹配测试的客户端IP');
        $this->addOption('cidr', null, Option::VALUE_OPTIONAL, 'CIDR 列表（逗号分隔），用于测试');
        $this->addOption('totp', null, Option::VALUE_OPTIONAL, 'TOTP 密钥（Base32编码），用于生成验证码');
        $this->addOption('code', null, Option::VALUE_OPTIONAL, '用于校验的 TOTP 验证码');
    }

    protected function execute(Input $input, Output $output): int
    {
        $output->writeln('<info>WiseAdmin 登录安全 — 自检测试</info>');
        $output->writeln('');

        $failed = 0;

        try {
            $encoded = Base32::encode('Hello, World!');
            $decoded = Base32::decode($encoded);
            $this->assert($output, 'Base32 encode/decode roundtrip', $decoded === 'Hello, World!');
        } catch (\Throwable $e) {
            $this->fail($output, 'Base32', $e->getMessage());
            $failed++;
        }

        $ip = (string) ($input->getOption('ip') ?? '192.168.1.100');
        $cidrs = (string) ($input->getOption('cidr') ?? '192.168.0.0/16,10.0.0.0/8');
        $cidrList = array_map('trim', explode(',', $cidrs));
        $matched = CidrMatcher::match($ip, $cidrList);
        $this->assert($output, "CIDR match: {$ip} ⊆ {" . implode(',', $cidrList) . '}', $matched);

        $secret = (string) ($input->getOption('totp') ?? '');
        $code = (string) ($input->getOption('code') ?? '');
        if ($secret === '') {
            $secret = (new TotpManager())->generateSecret();
        }
        try {
            $manager = new TotpManager();
            $timestep = (int) floor(time() / 30);
            $generated = $manager->generateAt($secret, $timestep);
            $output->writeln("  TOTP secret: <comment>{$secret}</comment>");
            $output->writeln("  TOTP code (current timestep): <comment>{$generated}</comment>");

            if ($code !== '') {
                $stubUser = new class implements TotpUserInterface {
                    public string $secret = '';
                    public function getTotpLabel(): string { return 'test'; }
                    public function getTotpUserType(): string { return 'admin'; }
                    public function getTotpSecret(): ?string { return $this->secret; }
                    public function setTotpSecret(?string $secret): void { $this->secret = $secret; }
                    public function getBackupCodes(): array { return []; }
                    public function setBackupCodes(array $codes): void {}
                    public function getRecoveryCodes(): array { return []; }
                    public function setRecoveryCodes(array $codes): void {}
                    public function isTotpEnabled(): bool { return true; }
                    public function setTotpEnabled(bool $enabled): void {}
                };
                $stubUser->secret = $secret;
                $ok = $manager->verify($stubUser, $code, 1);
                $this->assert($output, "TOTP verify code '{$code}'", $ok);
            }
        } catch (\Throwable $e) {
            $this->fail($output, 'TOTP', $e->getMessage());
            $failed++;
        }

        $output->writeln('');
        $output->writeln($failed === 0
            ? '<info>全部检测通过。</info>'
            : "<error>{$failed} 项检测失败。</error>");
        return $failed === 0 ? 0 : 1;
    }

    protected function assert(Output $output, string $label, bool $cond): void
    {
        $output->writeln('  ' . ($cond ? '<info>[ok]</info>' : '<error>[fail]</error>') . ' ' . $label);
    }

    protected function fail(Output $output, string $label, string $msg): void
    {
        $output->writeln("  <error>[error]</error> {$label}: {$msg}");
    }
}
