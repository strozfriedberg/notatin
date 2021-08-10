library "jenkins_shared_base" _
loadSharedLib()

def BASE_URL = 'ssh://git@stash.strozfriedberg.com/asdf'

pipeline {
  agent {
    label 'asdf-fedora'
  }
  stages {
    stage('Handle Upstream Trigger') {
      steps {
        script {
          common.HandleUpstreamTrigger(env, params, BASE_URL)
        }
      }
    }
    stage('Build and Run Tests') {
      steps {
        script {
          try {
            sh 'build/jenkins_build.sh'
          }
          finally {
            sh 'docker system prune -f'
          }
        }
      }
    }
    stage('Trigger Downstream') {
      steps {
        script {
          common.TriggerDownstream(env, params)
        }
      }
    }

  }
}