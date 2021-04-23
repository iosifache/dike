import React from 'react';
import ReactDOM from 'react-dom';
import {BrowserRouter, Route} from 'react-router-dom';
import {CookiesProvider} from 'react-cookie';

import MainForm from './routes/MainForm';
import Comparison from './routes/Comparison';
import Settings from './routes/Settings';
import Evaluation from './routes/Evaluation';

import './stylesheets/index.css';

import CONFIGURATION from './configuration/platform';

const ROUTES_CONFIGURATION = CONFIGURATION.routes;

ReactDOM.render(
  <CookiesProvider>
    <BrowserRouter>
      <Route
        exact
        path={ROUTES_CONFIGURATION.default.nameWithParameters}
        component={MainForm}
      />
      <Route
        path={ROUTES_CONFIGURATION.comparison.nameWithParameters}
        component={Comparison}
      />
      <Route
        path={ROUTES_CONFIGURATION.settings.nameWithParameters}
        component={Settings}
      />
      <Route
        path={ROUTES_CONFIGURATION.evaluation.nameWithParameters}
        component={Evaluation}
      />
    </BrowserRouter>
  </CookiesProvider>,
  document.getElementById('root'),
);
