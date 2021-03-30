import React from 'react';
import ReactDOM from 'react-dom';
import {BrowserRouter, Route} from 'react-router-dom';
import {CookiesProvider} from 'react-cookie';

import MainForm from './MainForm';
import Settings from './Settings';
import Evaluation from './Evaluation';

import './stylesheets/index.css';

ReactDOM.render(
  <CookiesProvider>
    <BrowserRouter>
      <Route exact path="/" component={MainForm} />
      <Route path="/settings" component={Settings} />
      <Route path="/evaluation/:model_name" component={Evaluation} />
    </BrowserRouter>
  </CookiesProvider>,
  document.getElementById('root'),
);
