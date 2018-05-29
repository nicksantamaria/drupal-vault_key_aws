<?php

/**
 * @file
 * Contains Drupal\vault\Plugin\KeyProvider\VaultKeyValueKeyProvider.
 */

namespace Drupal\vault_key_aws\Plugin\KeyProvider;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Component\Render\FormattableMarkup;
use Drupal\Component\Serialization\Json;
use Drupal\vault\VaultClient;

use Symfony\Component\DependencyInjection\ContainerInterface;

use Drupal\key\KeyInterface;
use Drupal\key\Plugin\KeyPluginFormInterface;
use Drupal\key\Plugin\KeyProviderBase;
use Drupal\key\Plugin\KeyProviderSettableValueInterface;

/**
 * Adds a key provider that fetches AWS credentials from HashiCorp Vault.
 *
 * @KeyProvider(
 *   id = "vault_aws",
 *   label = "Vault AWS",
 *   description = @Translation("This provider fetches AWS credentials from the HashiCorp Vault AWS secret engine."),
 *   storage_method = "vault_aws",
 *   key_value = {
 *     "accepted" = FALSE,
 *     "required" = FALSE
 *   }
 * )
 */
class VaultAWSKeyProvider extends KeyProviderBase implements KeyProviderSettableValueInterface, KeyPluginFormInterface {

  /**
   * The settings.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  protected $settings;

  /**
   * The Vault client.
   *
   * @var VaultClient
   */
  protected $client;

  /**
   * The logger.
   *
   * @var \Psr\Log\LoggerInterface
   */
  protected $logger;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    /** @var self $instance */
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    return $instance
      ->setClient($container->get('vault.vault_client'))
      ->setLogger($container->get('logger.channel.vault'));
  }

  /**
   * Sets client property.
   *
   * @param VaultClient $client
   *   The secrets manager client.
   *
   * @return self
   *   Current object.
   */
  public function setClient(VaultClient $client) {
    $this->client = $client;
    return $this;
  }

  /**
   * Sets logger property.
   *
   * @param \Psr\Log\LoggerInterface $logger
   *   The logger.
   *
   * @return self
   *   Current object.
   */
  public function setLogger(\Psr\Log\LoggerInterface $logger) {
    $this->logger = $logger;
    return $this;
  }

  /**
   * {@inheritdoc}
   */
  public function defaultConfiguration() {
    return [
      'secret_engine_mount' => 'aws/',
      'secret_path' => '',
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function getKeyValue(KeyInterface $key) {
    $state_key = $this->getStateKey($key);
    $lease = \Drupal::state()->get($state_key);
    if (!empty($lease)) {
      if ($lease['lease_expiry'] >= \Drupal::time()->getRequestTime()) {
        return $lease['data'];
      }
    }

    // @todo attempt to renew lease
    // @todo read new credentials when lease expires
    $path = $this->buildRequestPath("get", $key);
    try {
      $response = $this->client->read($path);

      $lease = [
        // JSON encode the value as the multi-key key type expects this data type.
        'data' => Json::encode($response->getData()),
        'lease_id' => $response->getLeaseId(),
        'lease_duration' => $response->getLeaseDuration(),
      ];
      $lease['lease_expiry'] = \Drupal::time()->getRequestTime() + (int) $lease['lease_duration'];
      \Drupal::state()->set($state_key, $lease);

      return $lease['data'];
    } catch (Exception $e) {
      $this->logger->critical('Unable to fetch secret ' . $key->id());
      return '';
    }
  }

  /**
   * {@inheritdoc}
   */
  public function setKeyValue(KeyInterface $key, $key_value) {
    // There's nothing to do here - we only support reading existing aws credentials.
  }

  /**
   * {@inheritdoc}
   */
  public function deleteKeyValue(KeyInterface $key) {
    // Revoke the lease.
    $state_key = $this->getStateKey($key);
    $lease = \Drupal::state()->get($state_key);
    if (!empty($lease)) {
      try {
        // @todo for some reason these tokens aren't being revoked. Get to the bottom of it.
        $path = '/sys/leases/revoke';
        $response = $this->client->put($path, ["lease_id" => $lease['lease_id']]);
      } catch (Exception $e) {
        $this->logger->critical('Unable to revoke lease on secret ' . $key->id());
      }
    }

    // Remove the lease from state API.
    \Drupal::state()->delete($state_key);
  }

  /**
   * {@inheritdoc}
   */
  public static function obscureKeyValue($key_value, array $options = []) {
    switch ($options['key_type_group']) {
      case 'authentication_multivalue':
        // Obscure the values of each element of the object to make it more
        // clear what the contents are.
        $options['visible_right'] = 4;

        $json = Json::decode($key_value);
        foreach ($json as $key => $value) {
          $json->{$key} = static::obscureKeyValue($key_value, $options);
        }
        $obscured_value = Json::encode($json);
        break;

      default:
        $obscured_value = parent::obscureKeyValue($key_value, $options);
    }

    return $obscured_value;
  }

  /**
   * {@inheritdoc}
   */
  public function buildConfigurationForm(array $form, FormStateInterface $form_state) {
    $client = \Drupal::service('vault.vault_client');
    $vault_config = \Drupal::config('vault.settings');
    $provider_config = $this->getConfiguration();
    $new = empty($form_state->getStorage()['key_value']['current']);

    $form['secret_engine_mount'] = [
      '#type' => 'select',
      '#title' => $this->t('Secret Engine Mount'),
      '#description' => $this->t('The Key/Value secret engine mount point.'),
      '#field_prefix' => sprintf('%s/%s/', $vault_config->get('base_url'), $client::API),
      '#required' => TRUE,
      '#default_value' => $provider_config['secret_engine_mount'],
      '#disabled' => !$new,
      '#options' => [],
    ];

    foreach ($client->listSecretEngineMounts(['aws']) as $mount => $info) {
      $form['secret_engine_mount']['#options'][$mount] = $mount;
    }

    $form['secret_path'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Secret Path'),
      '#description' => $this->t('The path prefix where the secret is stored.'),
      '#default_value' => $provider_config['secret_path'],
      '#disabled' => !$new,
    ];

    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function validateConfigurationForm(array &$form, FormStateInterface $form_state) {
    $key_provider_settings = $form_state->getValues();

    // Ensure secret path is only url safe characters.
    if (preg_match('/[^a-z_\-\/0-9]/i', $key_provider_settings['secret_path'])) {
      $form_state->setErrorByName('secret_path', $this->t('Secret Path Prefix only supports the following characters: a-z 0-9 . - _ /'));
      return;
    }
  }

  /**
   * {@inheritdoc}
   */
  public function submitConfigurationForm(array &$form, FormStateInterface $form_state) {
    $this->setConfiguration($form_state->getValues());
  }

  /**
   * Builds the URL endpoint.
   *
   * @param string $action
   * @param KeyInterface $key
   * @param string $lease_id
   * @return string
   */
  protected function buildRequestPath(string $action, KeyInterface $key, $lease_id = NULL) {
    $provider_config = $this->getConfiguration();

    switch ($action) {
      case 'get':
        $url = new FormattableMarkup("/:secret_engine_mount:endpoint/:secret_path", [
          ':secret_engine_mount' => $provider_config['secret_engine_mount'],
          ':endpoint' => 'creds',
          ':secret_path' => $provider_config['secret_path'],
        ]);
        break;

      case 'revoke':
        $url = new FormattableMarkup("/sys/leases/revoke/:lease_id", [
          ':lease_id' => $lease_id,
        ]);
        break;
    }

    return (string) $url;
  }

  /**
   *
   */
  protected function getStateKey(KeyInterface $key) {
    $state_key = sprintf('vault_key_aws.%s', $key->id());
    return $state_key;
  }

}
