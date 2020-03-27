import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Environment } from './environment';

@Injectable({
  providedIn: 'root'
})
export class HomeService {

  environment: Environment;

  constructor(private http: HttpClient) {
    this.environment = new Environment();
  }

  post_message(body: object) {
    return this.http.post(this.environment.urlHome + '/postmsg', body);
  }

  post_message_sign(body: object) {
    return this.http.post(this.environment.urlHome + '/sign', body);
  }

  get_message() {
    return this.http.get(this.environment.urlHome + '/getmsg');
  }

  get_publicKey() {
    return this.http.get(this.environment.urlHome + '/pubkey');
  }
}
