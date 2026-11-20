param location string = resourceGroup().location
param name string = 'netaudit'
param image string
param containerAppEnvironmentId string = ''

@description('GHCR packages are private by default, so a pull secret is usually needed.')
param registryUserName string = ''
param registryPassword string = ''

var ingressEnabled = true

resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${name}-env'
  location: location
  properties: {}
}

resource app 'Microsoft.App/containerApps@2024-03-01' = {
  name: name
  location: location
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      ingress: {
        external: ingressEnabled
        targetPort: 8000
        transport: 'http'
      }
      registries: empty(registryPassword) ? [] : [ {
        server: 'ghcr.io'
        username: registryUserName
        passwordSecretRef: 'registry-password'
      } ]
      secrets: empty(registryPassword) ? [] : [ {
        name: 'registry-password'
        value: registryPassword
      } ]
    }
    template: {
      containers: [
        {
          name: name
          image: image
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          probe: {
            liveness: [ {
              path: '/healthz'
              port: 8000
              intervalSeconds: 30
              timeoutSeconds: 3
            } ]
          }
        }
      ]
      scale: {
        minReplicas: 0
        maxReplicas: 1
      }
    }
  }
}

output url string = 'https://${app.properties.configuration.ingress.fqdn}'
