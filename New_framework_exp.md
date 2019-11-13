# Changes
1. Delete the call back function, since the tornado 6.0 will no longer support this function
2. We use `res = tornado_requests.request` instead of using tornado asynchonize client to send request.
[tornado_requests.request](https://github.com/cjustacoder/keylime/blob/469aa7bf55e68b52db3d6ded0b779ca4726b2a38/keylime/cloud_verifier_tornado.py#L343-L344)
3. Since we don't have call-back function, we directly handle the response in the same function which we use to send the request.
[merge callback function into request function](https://github.com/cjustacoder/keylime/blob/469aa7bf55e68b52db3d6ded0b779ca4726b2a38/keylime/cloud_verifier_tornado.py#L347-L378)
4. Since the tornado server is still asynchonized, the response is a `future` objct, hence we need to use `await` keywords before the response.
[await](https://github.com/cjustacoder/keylime/blob/469aa7bf55e68b52db3d6ded0b779ca4726b2a38/keylime/cloud_verifier_tornado.py#L345)
5. Since we need to use keyword `await`, (almost) all the handling function need to add keyword `async` before `def`.
[async](https://github.com/cjustacoder/keylime/blob/469aa7bf55e68b52db3d6ded0b779ca4726b2a38/keylime/cloud_verifier_tornado.py#L332)
6. Outside the asynchonized loop, we use `asyncio.ensure_future` to invoke with these asynchonized function to ensure we get concrete feedback inside the future object. [asyncio.ensure_future](https://github.com/cjustacoder/keylime/blob/469aa7bf55e68b52db3d6ded0b779ca4726b2a38/keylime/cloud_verifier_tornado.py#L267)

# Note 
1. I just re-write my original code into the new structure they provided, and make sure the code is able to run. All the original functions are normal after re-write, but I havn't test the newly added function yet
2. The approach, multi-verifier running on the same machine with different port, is not avaliable now. You can only use two VMs approach to test the code
3. Since some support library has been changed (so far I know is provider_verifier_common.py and revocation_notifier.py), you need to run `setup.py install` again.

# In progress...
1. Test on new functions on two VMs
2. Check the response under current framework
3. Handle the GET request inside the get handler

