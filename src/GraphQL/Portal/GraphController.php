<?php


namespace Smile\Common\GraphQL\Portal;

use GraphQL\Error\DebugFlag;
use GraphQL\GraphQL;
use GraphQL\Type\Schema;
use Hyperf\Contract\ConfigInterface;
use Hyperf\HttpServer\Annotation\Controller;
use Hyperf\HttpServer\Annotation\Middleware;
use Hyperf\HttpServer\Annotation\RequestMapping;
use GraphQL\Error\Error;
use Hyperf\Redis\Redis;
use Hyperf\Utils\ApplicationContext;
use Psr\Http\Message\ResponseInterface;
use Smile\Common\GraphQL\Factory\GraphTypeFactory;
use Smile\Common\Support\Entity\Result;
use Smile\Common\Support\Exception\BusinessException;
use Smile\Common\Support\Middleware\LoginMiddleware;
use Smile\Common\Support\Parent\BaseController;
use Smile\Common\Support\Util\SessionUtil;

/**
 * Class GraphController
 * @package App\Support\GraphQL
 * @Controller()
 */
class GraphController extends BaseController
{
    /**
     * @Middleware(LoginMiddleware::class)
     * @RequestMapping(path="/api/graph/[{action}]")
     * @param GraphTypeFactory $typeFactory
     * @param ConfigInterface $config
     * @return ResponseInterface|Result
     */
    public function root(GraphTypeFactory $typeFactory, ConfigInterface $config)
    {
        $schema = new Schema([
            'query' => $typeFactory->get($config->get('smile.graph.query_root_class')),
            'mutation' => $typeFactory->get($config->get('smile.graph.mutation_root_class')),
        ]);

        $query = $this->request->input('query');
        $variables = $this->request->input('variables');
        $isDebug = $this->request->has('debug');

        $rootValue = [];

        // 个人权限
        $accessScope = SessionUtil::getAccessScope();

        // 系统需验证权限
        $redis = ApplicationContext::getContainer()->get(Redis::class);
        $resourceAll = json_decode($redis->get('resourceAll'));

        try {
            $output = GraphQL::executeQuery($schema, $query, $rootValue, [], $variables, null, null, null, $accessScope, $resourceAll)
                ->setErrorsHandler(function (array $errors, callable $formatter) use ($isDebug) {
                    if ($isDebug) {
                        return array_map($formatter, $errors);
                    } else {
                        /** @var Error $error */
                        $error = array_pop($errors);
                        if (empty($error->getPrevious())) {
                            throw $error;
                        } else {
                            throw $error->getPrevious();
                        }
                    }
                })
                ->toArray(
                    $isDebug ? DebugFlag::INCLUDE_DEBUG_MESSAGE | DebugFlag::RETHROW_INTERNAL_EXCEPTIONS : false
                );
        } catch (\Throwable $e) {
            throw new BusinessException(401, $e->getMessage());
        }

        if (!array_key_exists('data', $output)) {
            return $this->response->json(Result::error(
                $config->get('smile.system_error_code', 500),
                '系统错误，请联系管理员',
                $isDebug ? $output : null
            ))->withStatus(500);
        }

        return Result::success($output['data']);
    }
}
