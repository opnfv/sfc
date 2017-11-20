FROM opnfv/functest-core

ARG REF=master
ARG OPNFV_TAG=master
ARG OPENSTACK_TAG=stable/pike

RUN apk --no-cache add --update sshpass && \
    wget -q -O- https://git.opnfv.org/functest/plain/upper-constraints.txt?h=$OPNFV_TAG | \
        sed /#egg=sfc/d \
    > upper-constraints.txt && \
    git clone https://gerrit.opnfv.org/gerrit/sfc /src/sfc && \
    (cd /src/sfc && git fetch origin $REF && git checkout FETCH_HEAD) && \
    pip install --no-cache-dir -cupper-constraints.txt \
        -chttps://git.openstack.org/cgit/openstack/requirements/plain/upper-constraints.txt?h=$OPENSTACK_TAG \
        /src/sfc && \
    rm -r upper-constraints.txt /src/sfc
COPY testcases.yaml /usr/lib/python2.7/site-packages/functest/ci/testcases.yaml
CMD ["bash","-c","prepare_env start && run_tests -t all"]
