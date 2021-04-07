const CONFIGURATION = {
  api: {
    baseAddress: 'https://127.0.0.1:3804',
    routes: {
      getMalwareFamilies: 'get_malware_families',
      getEvaluation: 'get_evaluation',
      getConfiguration: 'get_configuration',
      createTicket: 'create_ticket',
      getTicket: 'get_ticket',
      publish: 'publish',
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
};

export default CONFIGURATION;
