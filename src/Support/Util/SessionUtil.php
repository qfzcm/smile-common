<?php


namespace Smile\Common\Support\Util;


use Hyperf\Contract\ConfigInterface;
use Hyperf\Utils\ApplicationContext;
use Hyperf\Utils\Context;
use Psr\Http\Message\ServerRequestInterface;
use Smile\Common\Support\Constants\Vistor;
use Smile\Common\Support\Entity\SessionPayloadEntity;
use Smile\Common\Support\Exception\UnauthorizedException;
use Smile\Common\Support\Middleware\LoginMiddleware;

class SessionUtil
{
    const VISITOR_ID = 'VISITOR';

    protected static function _getUserId(): string
    {
        /** @var ServerRequestInterface $request */
        $request = Context::get(ServerRequestInterface::class);

        if (empty($request)) {
            return Vistor::VISITOR_ID;
        }

        /** @var SessionPayloadEntity $payload */
        $payload = $request->getAttribute(LoginMiddleware::PAYLOAD_KEY);

        if (empty($payload) || empty($payload->userId)) {
            return Vistor::VISITOR_ID;
        }

        return $payload->userId;
    }

    public static function getUserId(bool $allowVisitor = false)
    {
        $userId = self::_getUserId();
        if (!$allowVisitor && $userId == self::VISITOR_ID) {
            /** @var ConfigInterface $config */
            $config = ApplicationContext::getContainer()->get(ConfigInterface::class);

            throw new UnauthorizedException(
                $config->get('smile.unauthorized_message', '请您登录后再进行操作'),
                $config->get('smile.unauthorized_code', 400)
            );
        }

        return $userId;
    }

    protected static function _getProviderId()
    {
        /** @var ServerRequestInterface $request */
        $request = Context::get(ServerRequestInterface::class);

        if (empty($request)) {
            return 0;
        }

        /** @var SessionPayloadEntity $payload */
        $payload = $request->getAttribute(LoginMiddleware::PAYLOAD_KEY);

        if (empty($payload) || empty($payload->providerId)) {
            return 0;
        }

        return $payload->providerId;
    }

    public static function getProviderId()
    {
        $providerId = self::_getProviderId();
        if ($providerId == 0) {
            /** @var ConfigInterface $config */
            $config = ApplicationContext::getContainer()->get(ConfigInterface::class);

            throw new UnauthorizedException(
                $config->get('smile.unauthorized_message', '您还不是服务商'),
                $config->get('smile.unauthorized_code', 400)
            );
        }

        return $providerId;
    }

    protected static function _getStaffId()
    {
        /** @var ServerRequestInterface $request */
        $request = Context::get(ServerRequestInterface::class);

        if (empty($request)) {
            return 0;
        }

        /** @var SessionPayloadEntity $payload */
        $payload = $request->getAttribute(LoginMiddleware::PAYLOAD_KEY);

        if (empty($payload) || empty($payload->staffId)) {
            return 0;
        }

        return $payload->staffId;
    }

    public static function getStaffId()
    {
        $staff = self::_getStaffId();
        if ($staff == 0) {
            /** @var ConfigInterface $config */
            $config = ApplicationContext::getContainer()->get(ConfigInterface::class);

            throw new UnauthorizedException(
                $config->get('smile.unauthorized_message', '您还不是服务商员工'),
                $config->get('smile.unauthorized_code', 400)
            );
        }

        return $staff;
    }

    public static function getAccessScope(): array
    {
        /** @var ServerRequestInterface $request */
        $request = Context::get(ServerRequestInterface::class);

        if (empty($request)) {
            return [];
        }

        /** @var SessionPayloadEntity $payload */
        $payload = $request->getAttribute(LoginMiddleware::PAYLOAD_KEY);

        if (empty($payload) || empty($payload->staffId)) {
            return [];
        }

        return $payload->accessScope;
    }

    public static function isVisitor()
    {
        return self::_getUserId() == Vistor::VISITOR_ID;
    }
}