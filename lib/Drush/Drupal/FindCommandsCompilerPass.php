<?php
namespace Drush\Drupal;

use Drush\Log\LogLevel;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\Reference;

/**
 * This compiler pass is added to Drupal's ContainerBuilder by our own
 * subclass of DrupalKernel.  Our DrupalKernel subclass knows which
 * compiler passes to add because they are registered to it via its
 * 'alter()' method. This happens in DrupalBoot8/9/10 immediately after the
 * DrupalKernel object is created.
 *
 * Having been thus added, this compiler pass will then be called during
 * $kernel->boot(), when Drupal's dependency injection container is being
 * compiled.  Since we cannot use the container at this point (since its
 * initialization is not yet complete), we instead alter the definition of
 * a storage class in the container to add more setter injection method
 * calls to 'addCommandReference'.
 *
 * Later, after the container has been completely initialized, we can
 * fetch the storage class from the DI container (perhaps also via
 * injection from a reference in the container).  At that point, we can
 * request the list of Console commands that were added via the
 * (delayed) call(s) to addCommandReference.
 *
 * Documentation:
 *
 * http://symfony.com/doc/2.7/components/dependency_injection/tags.html#create-a-compilerpass
 */
class FindCommandsCompilerPass implements CompilerPassInterface
{
    protected $storageClassId;
    protected $tagId;

    public function __construct($storageClassId, $tagId)
    {
        $this->storageClassId = $storageClassId;
        $this->tagId = $tagId;
    }

    public function process(ContainerBuilder $container)
    {
        drush_log(dt("process !storage !tag", ['!storage' => $this->storageClassId, '!tag' => $this->tagId]), LogLevel::DEBUG);
        // We expect that our called registered the storage
        // class under the storage class id before adding this
        // compiler pass, but we will test this presumption to be sure.
        if (!$container->has($this->storageClassId)) {
            drush_log(dt("storage class not registered"), LogLevel::DEBUG);
            return;
        }

        $definition = $container->findDefinition(
            $this->storageClassId
        );

        $taggedServices = $container->findTaggedServiceIds(
            $this->tagId
        );
        foreach ($taggedServices as $id => $tags) {
            drush_log(dt("found tagged service !id", ['!id' => $id]), LogLevel::DEBUG);
            $definition->addMethodCall(
                'addCommandReference',
                array(new Reference($id))
            );
        }
    }
}
