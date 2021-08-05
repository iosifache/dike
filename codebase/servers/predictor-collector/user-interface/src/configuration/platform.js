const CONFIGURATION = {
  routes: {
    default: {
      name: '/',
      nameWithParameters: '/',
    },
    comparison: {
      name: '/comparison',
      nameWithParameters: '/comparison/:model_name/:file_hash',
    },
    settings: {
      name: '/settings',
      nameWithParameters: '/settings',
    },
    evaluation: {
      name: '/evaluation',
      nameWithParameters: '/evaluation/:model_name',
    },
  },
  api: {
    apiPort: '3805',
    routes: {
      getMalwareFamilies: '/get_malware_families',
      getEvaluation: '/get_evaluation',
      getConfiguration: '/get_configuration',
      getFeatures: '/get_features',
      createTicket: '/create_ticket',
      getTicket: '/get_ticket',
      publish: '/publish',
    },
    statuses: {
      success: 'success',
      unfinished: 'unfinished',
      error: 'error',
    },
  },
  particles: {
    enable: false,
    configuration: {
      particles: {
        number: {
          value: 200,
        },
        color: {
          value: '#fff',
        },
        opacity: {
          value: 1,
        },
        line_linked: {
          color: '#fff',
          opacity: 0.5,
          width: 2,
        },
        move: {
          speed: 1,
        },
      },
    },
  },
  decimalsAccuracy: 2,
  modelNameLength: 64,
  fileHashLength: 64,
};

export default CONFIGURATION;
