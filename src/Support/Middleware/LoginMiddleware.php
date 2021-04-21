<?php


namespace Smile\Common\Support\Middleware;


use Hyperf\Contract\ConfigInterface;
use Hyperf\Di\Annotation\Inject;
use Hyperf\Utils\Context;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Smile\Common\Support\Constants\Vistor;
use Smile\Common\Support\Entity\SessionPayloadEntity;
use Smile\Common\Support\Exception\UnauthorizedException;
use App\Storage\System\Model\Staff;
use App\Storage\System\Model\StaffRole;
use App\Storage\System\Model\StaffResource;



class LoginMiddleware implements MiddlewareInterface
{
    const PAYLOAD_KEY = '';

    /**
     * @Inject()
     * @var ConfigInterface
     */
    protected ConfigInterface $config;

    /**
     * @inheritDoc
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $userId = $request->getHeader('X-User-Id')[0] ?? Vistor::VISITOR_ID;
        $providerId = $request->getHeader('X-Provider-Id')[0] ?? '';
        $staffId = $request->getHeader('X-Staff-Id')[0] ?? '';
        $changeAuthAt = $request->getHeader('X-Change-Auth-At')[0] ?? '';
        $params = $request->getQueryParams();

        if (array_key_exists('debugUser', $params) && env('APP_ENV') != 'production') {
            $userId = $params['debugUser'];
        }

        if (array_key_exists('debugProviderId', $params) && env('APP_ENV') != 'production') {
            $providerId = $params['debugProviderId'];
            $staffId = $params['staffId'];
            $changeAuthAt = '2147483647';
            $request = $request->withaddedHeader('Is-Provider', '1');
        }

        if (empty($userId) && !$request->getHeader('Is-Provider')) {
            throw new UnauthorizedException(
                $this->config->get('smile.unauthorized_message', '请您登录后再进行操作'),
                $this->config->get('smile.unauthorized_code', 400)
            );
        }

        $accessScope = [];
        if ($request->getHeader('Is-Provider')) {
            if (empty($providerId) || empty($staffId)) {
                throw new UnauthorizedException(
                    $this->config->get('smile.unauthorized_message', '您还不是服务商'),
                    $this->config->get('smile.unauthorized_code', 400)
                );
            }
            $staff = Staff::findFromCache($staffId);

            if ($staff) {
                if ($staff['isDisable'] == 1) {
                    throw new UnauthorizedException(
                        $this->config->get('smile.unauthorized_message', '账号已停用'),
                        $this->config->get('smile.unauthorized_code', 400)
                    );
                }
                if ($staff['isAdmin']) {
                    $accessScope = [['all']];
                } else {
                    $role = StaffRole::findFromCache($staff->roleId);
                    foreach ($role['resources'] as $item) {
                        $resource = StaffResource::findFromCache($item);
                        $accessScope[] = $resource['routes'];
                    }
                }
                if (strtotime($staff['changeAuthAt']) > $changeAuthAt) {
                    throw new UnauthorizedException(
                        $this->config->get('smile.unauthorized_message', 'Token已失效，请重新登录'),
                        $this->config->get('smile.unauthorized_code', 400)
                    );
                }
            }
        }

        if ($userId && !$staffId && !$providerId && !$request->getHeader('Is-Provider')) {
            $accessScope = [['all']];
        }


        $sessionPayload = new SessionPayloadEntity();
        $sessionPayload->userId = $userId;
        $sessionPayload->providerId = $providerId;
        $sessionPayload->staffId = $staffId;
        $sessionPayload->accessScope = $accessScope;

        $request = Context::override(ServerRequestInterface::class, fn() => $request->withAttribute(self::PAYLOAD_KEY, $sessionPayload));

        return $handler->handle($request);
    }
}