import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormControl, FormGroup, Validators } from '@angular/forms';
import { HttpErrorResponse } from '@angular/common/http';
import { Router } from '@angular/router';
import { HomeService } from '../../services/home.service';
import * as bcu from 'bigint-crypto-utils';
import * as myrsa from 'rsa';
import * as bc from 'bigint-conversion';

@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css'],
  providers: [HomeService]
})
export class HomeComponent implements OnInit {

  homeForm: FormGroup;

  validation_messages: any;

  response: string;

  decrypted: string;

  verified: string;

  publicKey: myrsa.PublicKey;

  keyPair: myrsa.KeyPair;

  r: BigInt;

  _ONE: BigInt = BigInt(1);

  constructor(private homeService: HomeService, private router: Router, private formBuilder: FormBuilder) {
    this.homeForm = this.formBuilder.group({
      message: new FormControl('', Validators.compose([
        Validators.required,
        Validators.pattern(/^[a-zA-Z0-9_\s]{1,100}$/)])),
    });
  }

  async ngOnInit() {
    this.validation_messages = {
      message: [
        {type: 'required', message: 'Message is required'},
        {type: 'pattern', message: 'Email must be valid. Must contain between 1 and 100 characters'}
      ]
    };
    this.keyPair = await myrsa.generateRandomKeys();
    console.log(this.keyPair);
    await this.getPublicKey();
  }

  async getPublicKey() {
    this.homeService.get_publicKey()
      .subscribe(
        res => {
          this.publicKey = new myrsa.PublicKey(bc.hexToBigint(res["e"]),bc.hexToBigint(res["n"]))
          console.log(this.publicKey);
        },
        err => {
          console.log(err);
          this.handleError(err);
        }
      );
  }

  async post_message() {
    const c = this.publicKey.encrypt(bc.textToBigint(this.homeForm.value.message));
    const message = {
      msg: bc.bigintToHex(c)
    };
    this.homeService.post_message(message)
      .subscribe(
        res => {
          this.decrypted = bc.bigintToText(bc.hexToBigint(res['msg']));
        },
        err => {
          console.log(err);
          this.handleError(err);
        });
  }

  async sign_message() {
    const m = bc.bigintToHex(bc.textToBigint(this.homeForm.value.message));
    const message = {
      msg: m
    };
    this.homeService.post_message_sign(message)
      .subscribe(
        res => {
          const s = bc.hexToBigint(res['msg']);
          const m = this.publicKey.verify(s);
          this.verified = bc.bigintToText(m);
        },
        err => {
          console.log(err);
          this.handleError(err);
        });
  }

  async blind_sign_message() {
    // Generate the blinding factor
    const m = bc.textToBigint(this.homeForm.value.message);
    do {
      this.r = await bcu.prime(bcu.bitLength(this.publicKey.n))
    }
    while (!(bcu.gcd(this.r, this.publicKey.n) === this._ONE))
    // Generate the blind message
    const b = await bc.bigintToHex((m*this.publicKey.encrypt(this.r))%this.publicKey.n);
    const message = {
      msg: b
    };
    this.homeService.post_message_sign(message)
      .subscribe(
        async res => {
          const bs = bc.hexToBigint(res['msg']);
          const s = await (bs*bcu.modInv(this.r, this.publicKey.n))%this.publicKey.n;
          const m = await this.publicKey.verify(s);
          document.getElementById('blind-sign-verified').innerHTML =  'The message verified is: ' + bc.bigintToText(m) as string;
        },
        err => {
          console.log(err);
          this.handleError(err);
        });
  }

  async get_message() {
    this.homeService.get_message()
      .subscribe(
        res => {
          this.response = res['msg'];
        },
        err => {
          console.log(err);
          this.handleError(err);
        }
      );
  }

  private handleError(err: HttpErrorResponse) {
    if ( err.status === 500 ) {
      this.homeForm.get('message').setErrors({error: true});
    }
  }

}
