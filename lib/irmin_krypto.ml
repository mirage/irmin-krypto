(*
 * Copyright (c) 2013-2015 Thomas Gazagnaire <thomas@gazagnaire.org>
 * Copyright (c) 2015 Mounir Nasr Allah <mounir@nasrallah.co>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Lwt.Infix

module Log = Log.Make(struct let section = "KRYPO" end)

module type CTR = Nocrypto.Cipher_block.S.CTR

module type CIPHER = sig
  val encrypt: Cstruct.t -> Cstruct.t
  val decrypt: Cstruct.t -> Cstruct.t
end

module type KEYS = sig
  type t
  val data: t
  val header: t
end

module CTR (K:Irmin.Hash.S) (KS: KEYS with type t = K.t) (C:CTR) = struct

    type header = Cstruct.t

    let key_data = C.of_secret (K.to_raw KS.data)
    let key_header = C.of_secret (K.to_raw KS.header)
    let header_length = K.digest_size

    let compute_header v =
      let tmp = K.to_raw (K.digest v) in
      let res = Cstruct.create header_length in
      Cstruct.blit tmp 0 res 0 header_length;
      res

    let extract_header blob =
      let res = Cstruct.create header_length in
      Cstruct.blit blob 0 res 0 header_length;
      res

    let inject_header ~header blob =
      let len_blob = Cstruct.len blob in
      let res = Cstruct.create (header_length + len_blob) in
      Cstruct.blit header 0 res 0 header_length;
      Cstruct.blit blob 0 res header_length len_blob;
      res

    let extract_value blob =
      let len_blob = Cstruct.len blob in
      let len = len_blob - header_length in
      let res = Cstruct.create len in
      Cstruct.blit blob header_length res 0 len;
      res

    let encrypt value =
       let ctr_data   = compute_header value in
       let enc_data   = C.encrypt ~key:key_data ~ctr:ctr_data value in
       let ctr_header =
         Cstruct.sub (K.to_raw (K.digest enc_data)) 0 header_length
       in
       let enc_header = C.encrypt ~key:key_header ~ctr:ctr_header ctr_data in
       inject_header ~header:enc_header enc_data

    let decrypt cstr =
      let enc_header = extract_header cstr in
      let enc_value  = extract_value cstr in
      let ctr_header =
        Cstruct.sub (K.to_raw (K.digest enc_value)) 0 header_length
      in
      let dec_header = C.decrypt ~key:key_header ~ctr:ctr_header enc_header in
      let dec_value  =  C.decrypt ~key:key_data ~ctr:dec_header enc_value in
      let hash_value = K.to_raw (K.digest dec_value) in
      let hash_value = Cstruct.sub hash_value 0 header_length in
      match Cstruct.compare dec_header hash_value with
      | 0 -> dec_value
      | _ -> failwith "Data corruption !"

end


module GCM (K:Irmin.Hash.S) (KS: KEYS with type t = K.t) (C: CTR) = struct

    type header = {ctr:Cstruct.t; tag:Cstruct.t}

    let key_data = C.of_secret (K.to_raw KS.data)
    let key_header = C.of_secret (K.to_raw KS.header)
    let header_length = K.digest_size

    let compute_header v =
    let tmp = K.to_raw (K.digest v) in
    let res = Cstruct.create header_length in
    Cstruct.blit tmp 0 res 0 header_length;
    res

    let extract_header blob =
      let res = Cstruct.create header_length in
      Cstruct.blit blob 0 res 0 header_length;
      res

    let inject_header ~header blob =
      let len_blob = Cstruct.len blob in
      let res = Cstruct.create (header_length + len_blob) in
      Cstruct.blit header 0 res 0 header_length;
      Cstruct.blit blob 0 res header_length len_blob;
      res

    let extract_value blob =
      let len_blob = Cstruct.len blob in
      let len = len_blob - header_length in
      let res = Cstruct.create len in
      Cstruct.blit blob header_length res 0 len;
      res

    (** Encryption function *)
    let encrypt value =
       let ctr_data   = compute_header value in
       let enc_data   = C.encrypt ~key:key_data ~ctr:ctr_data value in
       let ctr_header = Cstruct.sub enc_data 0 header_length in
       let enc_header = C.encrypt ~key:key_header ~ctr:ctr_header ctr_data in
       inject_header ~header:enc_header enc_data

    (** Decryption function *)
    let decrypt cstr =
      let enc_header = extract_header cstr in
      let ctr_header = Cstruct.sub cstr header_length header_length in
      let dec_header = C.decrypt ~key:key_header ~ctr:ctr_header enc_header in
      let enc_value  = extract_value cstr in
      let dec_value  =  C.decrypt ~key:key_data ~ctr:dec_header enc_value in
      let hash_value = K.to_raw (K.digest dec_value) in
      let hash_value = Cstruct.sub hash_value 0 header_length in
      match Cstruct.compare dec_header hash_value with
      | 0 -> dec_value
      | _ -> failwith "Data corruption !"

end

module AO (C: CIPHER) (S:Irmin.AO_MAKER_RAW) (K:Irmin.Hash.S) (V:Irmin.RAW) =
struct

  module AO = S(K)(V)

  type key = AO.key
  type value = AO.value
  type t = AO.t

  let create config task = AO.create config task
  let task t = AO.task t
  let config t = AO.config t
  let mem t k = AO.mem t k
  let add t v = AO.add t (C.encrypt v)

  let read t key =
    AO.read t key >>= function
    | None   -> Lwt.return_none
    | Some v -> Lwt.return (Some (C.decrypt v))

  let read_exn t key =
    AO.read_exn t key >|= C.decrypt

  let iter t f =
    AO.iter t (fun k v ->
        let v = v >|= C.decrypt in
        f k v
      )

end
