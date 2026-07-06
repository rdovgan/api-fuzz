// CI pipeline for the AI-assisted API fuzzing harness.
//
// Runs one or more of the three layers (schemathesis / zap / ai) via ./run.sh
// against a target defined by job parameters + credentials, then publishes
// the JUnit report (schemathesis) and archives all other report artifacts
// (ZAP html/json/xml, ai-fuzzer html/json).
//
// Requirements on the Jenkins agent:
//   - Docker + Docker Compose v2, with network access to TARGET_URL/SPEC_URL
//     (this pipeline does not manage VPN/network setup for the agent).
//   - python3 + curl on the agent host itself (used by run.sh to fetch a fresh
//     spec snapshot and build reports/summary-*.md; degrades gracefully to
//     per-layer fetching/reporting only if either is missing).
//
// Required credentials (Jenkins credential store):
//   - api-fuzz-target-auth       (Secret text) — value sent in TARGET_AUTH_HEADER
//   - api-fuzz-anthropic-key     (Secret text) — Z.ai API key; only needed when
//     LAYER includes "ai" (the AI layer calls GLM models via Z.ai's
//     Anthropic-Messages-compatible endpoint, so the anthropic SDK is unchanged)
//
pipeline {
    agent any

    parameters {
        choice(
            name: 'LAYER',
            choices: ['schemathesis', 'zap', 'ai', 'all'],
            description: 'Which layer(s) to run.'
        )
        string(
            name: 'SPEC_URL',
            defaultValue: 'http://172.18.4.202/v3/api-docs',
            description: 'OpenAPI 3.0 document: a URL, or a local JSON/YAML file path reachable on the agent workspace.'
        )
        string(
            name: 'TARGET_URL',
            defaultValue: 'http://172.18.4.202',
            description: 'Base URL of the running service under test.'
        )
        string(
            name: 'TARGET_AUTH_HEADER',
            defaultValue: 'x-api-key',
            description: 'Header name the TARGET_AUTH secret is sent under.'
        )
        string(
            name: 'STH_EXAMPLES',
            defaultValue: '150',
            description: 'Schemathesis examples generated per operation.'
        )
        choice(
            name: 'AI_FAIL_ON',
            choices: ['fail', 'warn', 'never'],
            description: 'Severity that fails the build for the AI layer.'
        )
        booleanParam(
            name: 'ACKNOWLEDGE_ACTIVE_SCAN',
            defaultValue: false,
            description: 'Must be checked to run the ZAP layer (LAYER=zap or all) — ZAP performs an ACTIVE security scan against TARGET_URL. Only enable for authorized test/staging targets.'
        )
    }

    options {
        timestamps()
        disableConcurrentBuilds()
        timeout(time: 90, unit: 'MINUTES')
    }

    environment {
        TARGET_AUTH = credentials('api-fuzz-target-auth')
    }

    stages {
        stage('Guard: active scan authorization') {
            when {
                expression { params.LAYER == 'zap' || params.LAYER == 'all' }
            }
            steps {
                script {
                    if (!params.ACKNOWLEDGE_ACTIVE_SCAN) {
                        error("LAYER=${params.LAYER} runs ZAP's active scanner. Re-run with ACKNOWLEDGE_ACTIVE_SCAN=true only if you are authorized to actively test ${params.TARGET_URL}.")
                    }
                }
            }
        }

        stage('Write .env') {
            steps {
                script {
                    def anthropicKey = 'unused'
                    if (params.LAYER == 'ai' || params.LAYER == 'all') {
                        withCredentials([string(credentialsId: 'api-fuzz-anthropic-key', variable: 'KEY')]) {
                            anthropicKey = env.KEY
                        }
                    }
                    writeFile file: '.env', text: """\
SPEC_URL=${params.SPEC_URL}
TARGET_URL=${params.TARGET_URL}
TARGET_AUTH_HEADER=${params.TARGET_AUTH_HEADER}
TARGET_AUTH=${env.TARGET_AUTH}
ANTHROPIC_API_KEY=${anthropicKey}
ANTHROPIC_BASE_URL=https://api.z.ai/api/anthropic
FUZZ_MODEL=glm-5.2
FUZZ_MAX_PAYLOADS_PER_PARAM=12
AI_FAIL_ON=${params.AI_FAIL_ON}
STH_EXAMPLES=${params.STH_EXAMPLES}
"""
                }
            }
        }

        stage('Run') {
            steps {
                sh "./run.sh ${params.LAYER}"
            }
        }
    }

    post {
        always {
            junit testResults: 'reports/junit-*.xml', allowEmptyResults: true
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            sh 'docker compose --profile schemathesis --profile zap --profile ai down --remove-orphans || true'
            sh 'rm -f .env'
        }
    }
}
